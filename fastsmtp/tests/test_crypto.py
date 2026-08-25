"""Tests for envelope encryption of sensitive JSON columns.

The column these protect, ``recipients.webhook_headers``, holds third-party
bearer tokens. Two properties matter more than the round trip itself: a value
that cannot be decrypted must raise rather than degrade to an empty dict (a
webhook sent with no auth headers looks like a success and is not one), and a
value encrypted under an old key must stay readable while a new key is being
rolled out.
"""

import json

import pytest
from cryptography.fernet import Fernet
from fastsmtp.crypto import (
    ENVELOPE_MARKER,
    ENVELOPE_VERSION,
    DecryptionError,
    EncryptionError,
    KeyConfigurationError,
    build_cipher,
    decrypt_json,
    encrypt_json,
    is_encrypted,
)

KEY_A = "operator-key-alpha"
KEY_B = "operator-key-bravo"

HEADERS = {
    "Authorization": "Bearer sk-live-0123456789abcdef",
    "X-Signature": "sha256=deadbeef",
    "X-Tenant": "acme",
}


@pytest.fixture
def cipher_a():
    """A cipher holding only key A."""
    return build_cipher([KEY_A])


class TestBuildCipher:
    """Tests for turning operator-supplied strings into a cipher."""

    def test_no_keys_yields_no_cipher(self):
        """Test an empty key list disables encryption rather than failing."""
        assert build_cipher([]) is None

    def test_arbitrary_string_is_accepted_as_a_key(self):
        """Test an operator need not supply base64 of exactly 32 bytes."""
        cipher = build_cipher(["hunter2"])
        assert cipher is not None
        assert decrypt_json(encrypt_json(HEADERS, cipher), cipher) == HEADERS

    def test_empty_key_is_rejected(self):
        """Test an empty key raises instead of deriving a key from "".

        An empty entry is an unset environment variable, not a choice. Taking
        it would encrypt production data under a publicly guessable key.
        """
        with pytest.raises(KeyConfigurationError):
            build_cipher([""])

    def test_whitespace_only_key_is_rejected(self):
        """Test a whitespace-only key is treated the same as an empty one."""
        with pytest.raises(KeyConfigurationError):
            build_cipher(["   \t\n"])

    def test_rejection_names_the_offending_position(self):
        """Test the error identifies which entry is broken."""
        with pytest.raises(KeyConfigurationError, match=r"\[1\]"):
            build_cipher([KEY_A, ""])

    def test_a_bare_string_is_rejected(self):
        """Test one comma-separated string is not mistaken for a key list.

        ``str`` satisfies ``Sequence[str]``, so the type checker cannot catch
        this; iterating it would derive one key per character.
        """
        with pytest.raises(KeyConfigurationError, match="sequence"):
            build_cipher("a-single-key")

    def test_configuration_errors_are_encryption_errors(self):
        """Test callers can catch the whole family with one except clause."""
        assert issubclass(KeyConfigurationError, EncryptionError)
        assert issubclass(DecryptionError, EncryptionError)


class TestRoundTrip:
    """Tests that plaintext survives a trip through the envelope."""

    def test_realistic_headers_round_trip(self, cipher_a):
        """Test a realistic headers dict comes back identical."""
        assert decrypt_json(encrypt_json(HEADERS, cipher_a), cipher_a) == HEADERS

    def test_unicode_values_round_trip(self, cipher_a):
        """Test non-ASCII header values survive the JSON encoding."""
        value = {"X-Note": "café — 日本語", "X-Emoji": "\U0001f512"}
        assert decrypt_json(encrypt_json(value, cipher_a), cipher_a) == value

    def test_empty_dict_round_trips(self, cipher_a):
        """Test an empty headers dict is a value, not a missing one."""
        envelope = encrypt_json({}, cipher_a)
        assert is_encrypted(envelope)
        assert decrypt_json(envelope, cipher_a) == {}

    def test_nested_structures_round_trip(self, cipher_a):
        """Test the payload is not restricted to flat string values."""
        value = {"list": [1, 2, 3], "nested": {"a": None, "b": True}}
        assert decrypt_json(encrypt_json(value, cipher_a), cipher_a) == value

    def test_envelope_is_json_serializable(self, cipher_a):
        """Test the envelope can be stored in a JSONB column as-is."""
        envelope = encrypt_json(HEADERS, cipher_a)
        assert json.loads(json.dumps(envelope)) == envelope

    def test_envelope_shape(self, cipher_a):
        """Test the envelope carries only the marker and the ciphertext."""
        envelope = encrypt_json(HEADERS, cipher_a)
        assert envelope[ENVELOPE_MARKER] == ENVELOPE_VERSION
        assert isinstance(envelope["ciphertext"], str)
        assert set(envelope) == {ENVELOPE_MARKER, "ciphertext"}

    def test_ciphertext_does_not_contain_the_plaintext(self, cipher_a):
        """Test the stored blob does not leak the token it protects."""
        blob = json.dumps(encrypt_json(HEADERS, cipher_a))
        assert "sk-live-0123456789abcdef" not in blob
        assert "Authorization" not in blob

    def test_two_encryptions_differ_but_both_decrypt(self, cipher_a):
        """Test encryption is non-deterministic.

        Fernet embeds a timestamp and a random IV, so identical plaintext must
        not produce identical ciphertext; otherwise equal stored blobs would
        reveal that two recipients share a token.
        """
        first = encrypt_json(HEADERS, cipher_a)
        second = encrypt_json(HEADERS, cipher_a)
        assert first["ciphertext"] != second["ciphertext"]
        assert decrypt_json(first, cipher_a) == HEADERS
        assert decrypt_json(second, cipher_a) == HEADERS

    def test_non_serializable_value_raises(self, cipher_a):
        """Test a value JSON cannot represent fails loudly at encryption."""
        with pytest.raises(EncryptionError):
            encrypt_json({"when": object()}, cipher_a)


class TestIsEncrypted:
    """Tests for distinguishing an envelope from anything else."""

    @pytest.mark.parametrize("value", [None, [], "str", 0, {}, {"X-Token": "v"}, 3.5])
    def test_non_envelopes_are_false_and_never_raise(self, value):
        """Test any input type answers False rather than raising.

        This runs on every load of the column, including None and rows
        written before the feature existed.
        """
        assert is_encrypted(value) is False

    def test_envelope_is_true(self, cipher_a):
        """Test a freshly built envelope is recognised."""
        assert is_encrypted(encrypt_json(HEADERS, cipher_a)) is True

    def test_marker_alone_is_enough(self):
        """Test recognition depends on the marker, not on the payload.

        A malformed envelope must be routed to the decryption error path, not
        mistaken for legacy plaintext and returned as-is.
        """
        assert is_encrypted({ENVELOPE_MARKER: ENVELOPE_VERSION}) is True


class TestLegacyPlaintext:
    """Tests for rows written before encryption was enabled."""

    def test_plaintext_passes_through_with_a_cipher(self, cipher_a):
        """Test an unencrypted row is returned unchanged, not rejected."""
        value = {"X-Token": "v"}
        assert decrypt_json(value, cipher_a) == value

    def test_plaintext_passes_through_without_a_cipher(self):
        """Test the feature being off leaves stored values alone."""
        value = {"X-Token": "v"}
        assert decrypt_json(value, None) == value

    def test_passthrough_returns_the_same_object(self, cipher_a):
        """Test the passthrough does not copy or rebuild the dict."""
        value = {"X-Token": "v"}
        assert decrypt_json(value, cipher_a) is value


class TestDecryptionFailures:
    """Tests that an unreadable value raises instead of degrading."""

    def test_encrypted_value_without_a_key_raises(self, cipher_a):
        """Test a configured-away key is an error, not an empty result."""
        envelope = encrypt_json(HEADERS, cipher_a)
        with pytest.raises(DecryptionError) as excinfo:
            decrypt_json(envelope, None)
        assert "FASTSMTP_ENCRYPTION_KEYS" in str(excinfo.value)

    def test_wrong_key_raises(self, cipher_a):
        """Test a cipher that does not hold the writing key raises."""
        envelope = encrypt_json(HEADERS, cipher_a)
        with pytest.raises(DecryptionError):
            decrypt_json(envelope, build_cipher([KEY_B]))

    def test_wrong_key_message_mentions_rotation(self, cipher_a):
        """Test the message points at the likely cause: a dropped key."""
        envelope = encrypt_json(HEADERS, cipher_a)
        with pytest.raises(DecryptionError) as excinfo:
            decrypt_json(envelope, build_cipher([KEY_B]))
        message = str(excinfo.value).lower()
        assert "decrypt" in message
        assert "rotate" in message

    def test_tampered_ciphertext_raises(self, cipher_a):
        """Test Fernet's authentication is surfaced, not swallowed."""
        envelope = encrypt_json(HEADERS, cipher_a)
        envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"
        with pytest.raises(DecryptionError):
            decrypt_json(envelope, cipher_a)

    def test_unrelated_fernet_token_raises(self, cipher_a):
        """Test a valid token from a foreign key is still refused."""
        stranger = Fernet(Fernet.generate_key())
        envelope = {
            ENVELOPE_MARKER: ENVELOPE_VERSION,
            "ciphertext": stranger.encrypt(b"{}").decode(),
        }
        with pytest.raises(DecryptionError):
            decrypt_json(envelope, cipher_a)

    def test_authentic_token_holding_non_json_raises(self, cipher_a):
        """Test a token this key accepts but cannot parse still raises.

        Reachable if something other than this module ever writes an envelope.
        The payload is authentic, so Fernet is happy; the JSON layer is the
        only thing standing between that and a crash further up the stack.
        """
        envelope = {
            ENVELOPE_MARKER: ENVELOPE_VERSION,
            "ciphertext": cipher_a.encrypt(b"not json at all").decode(),
        }
        with pytest.raises(DecryptionError, match="JSON"):
            decrypt_json(envelope, cipher_a)

    def test_authentic_token_holding_a_json_array_raises(self, cipher_a):
        """Test the payload must be an object, not any JSON value."""
        envelope = {
            ENVELOPE_MARKER: ENVELOPE_VERSION,
            "ciphertext": cipher_a.encrypt(b"[1, 2, 3]").decode(),
        }
        with pytest.raises(DecryptionError, match="list"):
            decrypt_json(envelope, cipher_a)

    def test_unknown_version_raises(self, cipher_a):
        """Test a future envelope layout is refused, not guessed at."""
        envelope = encrypt_json(HEADERS, cipher_a)
        envelope[ENVELOPE_MARKER] = ENVELOPE_VERSION + 1
        with pytest.raises(DecryptionError, match="version"):
            decrypt_json(envelope, cipher_a)

    def test_missing_ciphertext_raises_decryption_error(self, cipher_a):
        """Test a malformed envelope raises DecryptionError, not KeyError."""
        with pytest.raises(DecryptionError):
            decrypt_json({ENVELOPE_MARKER: ENVELOPE_VERSION}, cipher_a)

    def test_non_string_ciphertext_raises_decryption_error(self, cipher_a):
        """Test a non-str ciphertext raises DecryptionError, not TypeError."""
        envelope = {ENVELOPE_MARKER: ENVELOPE_VERSION, "ciphertext": 12345}
        with pytest.raises(DecryptionError):
            decrypt_json(envelope, cipher_a)

    def test_malformed_envelope_is_checked_before_the_key(self):
        """Test a broken envelope with no cipher still raises cleanly."""
        with pytest.raises(DecryptionError):
            decrypt_json({ENVELOPE_MARKER: ENVELOPE_VERSION}, None)


class TestKeyRotation:
    """Tests for the property that makes rotating a key possible."""

    def test_old_key_still_decrypts_after_a_new_one_is_prepended(self, cipher_a):
        """Test adding a key ahead of the old one does not orphan any row.

        This is step one of a rotation: the new key is prepended and becomes
        the writer, while the superseded key stays configured so the existing
        rows keep opening.
        """
        envelope = encrypt_json(HEADERS, cipher_a)
        assert decrypt_json(envelope, build_cipher([KEY_B, KEY_A])) == HEADERS

    def test_dropping_the_old_key_before_backfilling_breaks_rows(self, cipher_a):
        """Test removing the writing key too early is a loud failure.

        The inverse of the test above, asserted so the ordering requirement is
        documented by a test rather than only by prose.
        """
        envelope = encrypt_json(HEADERS, cipher_a)
        with pytest.raises(DecryptionError):
            decrypt_json(envelope, build_cipher([KEY_B]))

    def test_new_rows_are_written_under_the_primary_key(self):
        """Test the first key encrypts, so new rows never need the old one."""
        envelope = encrypt_json(HEADERS, build_cipher([KEY_B, KEY_A]))
        assert decrypt_json(envelope, build_cipher([KEY_B])) == HEADERS
