"""Plain helpers shared by the MIME payload-extraction tests.

A module rather than fixtures in ``conftest.py``: these are called from inside
message builders and assertions, so reaching them through a fixture would mean
threading an argument into roughly thirty call sites for no gain.
``cli_harness.py`` next door is the same shape.

``test_raw_message_preservation.py`` deliberately keeps its own ``_envelope``.
It takes the recipients as arguments and sends from an external domain, which
is the situation those tests are about; folding it in here would cost every
call site a ``mail_from=`` and say nothing.
"""

from aiosmtpd.smtp import Envelope

# A PNG signature followed by filler. Real enough for the content-type and
# size assertions, and short enough to read in a failure message.
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"fake image data"


def envelope() -> Envelope:
    """An envelope as it stands after MAIL FROM and a single RCPT TO."""
    env = Envelope()
    env.mail_from = "sender@example.com"
    env.rcpt_tos = ["recipient@example.com"]
    return env
