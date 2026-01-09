"""End-to-end integration tests for SMTP server protocol handling.

Tests the SMTP server's ability to:
- Accept SMTP connections
- Handle EHLO/MAIL/RCPT/DATA commands
- Advertise correct capabilities

Note: Database integration is tested in test_smtp_integration.py with proper
mocking. These tests focus on SMTP protocol behavior.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiosmtplib
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from fastsmtp.config import Settings
from fastsmtp.db.models import Base, Domain, Recipient
from fastsmtp.smtp.server import SMTPServer


class TestSMTPProtocolE2E:
    """End-to-end tests for SMTP protocol behavior."""

    @pytest.fixture
    def smtp_settings(self) -> Settings:
        """Create settings for SMTP testing."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_e2e_key_12345",
            secret_key="test-e2e-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12570,  # Unique port
            smtp_tls_port=14680,
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
            smtp_max_message_size=1024 * 1024,
        )

    @pytest_asyncio.fixture
    async def smtp_server(self, smtp_settings: Settings):
        """Start SMTP server for testing."""
        server = SMTPServer(settings=smtp_settings)
        await server.start()
        await asyncio.sleep(0.1)  # Give server time to start
        yield server
        await server.stop()

    @pytest.mark.asyncio
    async def test_smtp_server_accepts_connection(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server accepts connections."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        assert smtp.is_connected
        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_server_ehlo_capabilities(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server advertises correct capabilities."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        response = await smtp.ehlo()
        assert response.code == 250

        # Verify expected capabilities
        assert smtp.supports_extension("SIZE")
        assert smtp.supports_extension("8BITMIME")
        assert smtp.supports_extension("SMTPUTF8")

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_server_mail_command(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server accepts MAIL FROM command."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()

        response = await smtp.mail("sender@example.com")
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_server_advertises_size(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that SMTP server advertises correct message size limit."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        response = await smtp.ehlo()
        assert response.code == 250

        # Check SIZE is advertised
        assert smtp.supports_extension("SIZE")

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_connection_reset(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test RSET command resets the mail transaction."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()

        # Start a transaction
        await smtp.mail("sender@example.com")

        # Reset should succeed
        response = await smtp.rset()
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_noop_command(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test NOOP command returns success."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        response = await smtp.noop()
        assert response.code == 250

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_connection_reuse_without_data(
        self,
        smtp_server,
        smtp_settings: Settings,
    ):
        """Test that connection can be reused for multiple MAIL transactions."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()

        # First transaction
        response1 = await smtp.mail("sender1@example.com")
        assert response1.code == 250
        await smtp.rset()

        # Second transaction
        response2 = await smtp.mail("sender2@example.com")
        assert response2.code == 250

        await smtp.quit()


class TestSMTPServerWithMockedDatabase:
    """Tests that verify SMTP handling with mocked database lookups."""

    @pytest.fixture
    def smtp_settings(self) -> Settings:
        """Create settings for SMTP testing."""
        return Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="test_mock_key_12345",
            secret_key="test-mock-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12571,  # Unique port
            smtp_tls_port=14681,
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
            smtp_max_message_size=1024 * 1024,
        )

    @pytest_asyncio.fixture
    async def smtp_server_with_mock(self, smtp_settings: Settings):
        """Start SMTP server with mocked database lookups."""
        # Mock the lookup_recipient function to simulate domain/recipient
        mock_domain = MagicMock()
        mock_domain.id = 1
        mock_domain.domain_name = "mock-test.example.com"
        mock_domain.is_enabled = True

        mock_recipient = MagicMock()
        mock_recipient.id = 1
        mock_recipient.domain_id = 1
        mock_recipient.local_part = "user"
        mock_recipient.webhook_url = "https://webhook.example.com/mock"
        mock_recipient.is_enabled = True

        async def mock_lookup(address, session):
            if address.endswith("@mock-test.example.com"):
                return mock_domain, mock_recipient, None
            return None, None, "Domain not configured"

        with (
            patch("fastsmtp.smtp.server.lookup_recipient", side_effect=mock_lookup),
            patch(
                "fastsmtp.smtp.server.FastSMTPHandler._process_and_persist_message",
                new_callable=AsyncMock,
            ) as mock_process,
        ):
            mock_process.return_value = None

            server = SMTPServer(settings=smtp_settings)
            await server.start()
            await asyncio.sleep(0.1)
            yield server
            await server.stop()

    @pytest.mark.asyncio
    async def test_smtp_accepts_valid_recipient(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test that SMTP server accepts emails to configured recipients."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        email_content = b"""\
From: sender@external.com
To: user@mock-test.example.com
Subject: Test Email
Message-ID: <mock-test-001@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

This is a test email.
"""

        errors, message = await smtp.sendmail(
            "sender@external.com",
            ["user@mock-test.example.com"],
            email_content,
        )

        assert errors == {}, f"SMTP returned errors: {errors}"
        assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_rejects_unknown_domain(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test that SMTP server rejects recipients from unknown domains."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        await smtp.ehlo()
        await smtp.mail("sender@external.com")

        with pytest.raises(aiosmtplib.SMTPRecipientRefused) as exc_info:
            await smtp.rcpt("user@unknown-domain.com")

        assert exc_info.value.code == 550

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_handles_multiple_recipients(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test sending to multiple recipients."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        email_content = b"""\
From: sender@external.com
To: user@mock-test.example.com, another@mock-test.example.com
Subject: Multi-recipient Test
Message-ID: <mock-multi-001@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Message to multiple recipients.
"""

        errors, message = await smtp.sendmail(
            "sender@external.com",
            ["user@mock-test.example.com", "another@mock-test.example.com"],
            email_content,
        )

        assert errors == {}
        assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_handles_multipart_email(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test that multipart emails are accepted."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        email_content = b"""\
From: sender@external.com
To: user@mock-test.example.com
Subject: Multipart Test
Message-ID: <mock-multipart-001@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

Plain text version.

--boundary123
Content-Type: text/html; charset="utf-8"

<html><body><p>HTML version.</p></body></html>

--boundary123--
"""

        errors, message = await smtp.sendmail(
            "sender@external.com",
            ["user@mock-test.example.com"],
            email_content,
        )

        assert errors == {}
        assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_connection_reuse(
        self,
        smtp_server_with_mock,
        smtp_settings: Settings,
    ):
        """Test sending multiple emails over a single connection."""
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        for i in range(3):
            email_content = f"""\
From: sender@external.com
To: user@mock-test.example.com
Subject: Connection Reuse Test {i}
Message-ID: <mock-reuse-{i:03d}@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Email number {i}.
""".encode()

            errors, message = await smtp.sendmail(
                "sender@external.com",
                ["user@mock-test.example.com"],
                email_content,
            )
            assert errors == {}
            assert "accepted" in message.lower()

        await smtp.quit()


class TestSMTPServerWithRealDatabase:
    """Tests that verify SMTP handling with a REAL database.

    These tests verify that the SMTP server correctly handles database
    operations when using UnthreadedController. Previously, aiosmtpd's
    Controller ran in a separate thread with its own event loop, causing
    "Future attached to a different loop" errors when SQLAlchemy's
    AsyncEngine was bound to the main event loop.

    With UnthreadedController, the SMTP server runs on the same event loop
    as the rest of the application, ensuring database operations work correctly.
    """

    @pytest.fixture
    def smtp_settings(self, postgres_url: str) -> Settings:
        """Create settings for SMTP testing with real PostgreSQL."""
        return Settings(
            database_url=postgres_url,
            root_api_key="test_real_db_key_12345",
            secret_key="test-real-db-secret-key",
            smtp_host="127.0.0.1",
            smtp_port=12572,  # Unique port for this test class
            smtp_tls_port=14682,
            smtp_verify_dkim=False,
            smtp_verify_spf=False,
            smtp_max_message_size=1024 * 1024,
        )

    @pytest_asyncio.fixture
    async def db_engine(self, smtp_settings: Settings):
        """Create database engine and tables."""
        engine = create_async_engine(
            smtp_settings.database_url,
            echo=False,
        )

        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

        yield engine

        await engine.dispose()

    @pytest_asyncio.fixture
    async def db_with_domain(self, db_engine):
        """Set up database with a test domain and recipient."""
        session_factory = async_sessionmaker(
            db_engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        async with session_factory() as session:
            # Create test domain
            domain = Domain(
                domain_name="real-test.example.com",
                is_enabled=True,
            )
            session.add(domain)
            await session.flush()

            # Create test recipient (catch-all)
            recipient = Recipient(
                domain_id=domain.id,
                local_part=None,  # Catch-all
                webhook_url="https://webhook.example.com/test",
                is_enabled=True,
            )
            session.add(recipient)
            await session.commit()

        yield db_engine

    @pytest_asyncio.fixture
    async def smtp_server_real_db(self, smtp_settings: Settings, db_with_domain):
        """Start SMTP server with real database - NO MOCKING.

        This fixture does NOT mock lookup_recipient or _process_and_persist_message.
        The SMTP handler will actually hit the database, which should trigger
        the event loop issue when Controller runs in a separate thread.

        CRITICAL: We must initialize the database engine on the MAIN event loop
        BEFORE starting the SMTP server. This simulates production where:
        1. Main app (FastAPI/uvicorn) initializes the engine on the main loop
        2. aiosmtpd's Controller starts in a separate thread with its own loop
        3. SMTP handler tries to use the engine that's bound to the main loop
        """
        from fastsmtp.db import session as db_session_module

        # Reset the module-level singletons
        original_engine = db_session_module._engine
        original_session = db_session_module._async_session
        db_session_module._engine = None
        db_session_module._async_session = None

        # Patch get_settings to return our test settings
        with patch("fastsmtp.db.session.get_settings", return_value=smtp_settings):
            # CRITICAL: Initialize the engine on THIS event loop (the main/test loop)
            # This simulates what happens in production when FastAPI initializes
            # the database before the SMTP server starts
            _ = db_session_module.get_engine()  # Force engine initialization
            session_factory = db_session_module.get_async_session_factory()

            # Verify the engine is initialized - do a simple query to ensure
            # the connection pool is bound to this loop
            async with session_factory() as session:
                await session.execute(text("SELECT 1"))

            # NOW start the SMTP server - with UnthreadedController it runs
            # on the SAME event loop, so database operations should work
            server = SMTPServer(settings=smtp_settings)
            await server.start()
            await asyncio.sleep(0.2)  # Give server time to start

            yield server

            await server.stop()

        # Clean up
        if db_session_module._engine:
            await db_session_module._engine.dispose()
        db_session_module._engine = original_engine
        db_session_module._async_session = original_session

    @pytest.mark.asyncio
    async def test_smtp_rcpt_with_real_database_lookup(
        self,
        smtp_server_real_db,
        smtp_settings: Settings,
    ):
        """Test RCPT TO command with real database lookup.

        This test verifies that RCPT TO correctly performs database lookups
        when using UnthreadedController. The fix ensures:
        - SMTP server runs on the same event loop as the test
        - Database operations work correctly without event loop mismatches
        - AsyncEngine singleton is used from the correct loop context
        """
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()

        # MAIL FROM should work (no database access)
        response = await smtp.mail("sender@external.com")
        assert response.code == 250

        # RCPT TO triggers database lookup - this is where the bug manifests
        # The handler runs in Controller's thread, but the database engine
        # is bound to the pytest event loop
        response = await smtp.rcpt("user@real-test.example.com")
        assert response.code == 250, f"Expected 250 OK, got {response.code}: {response.message}"

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_full_email_with_real_database(
        self,
        smtp_server_real_db,
        smtp_settings: Settings,
    ):
        """Test sending a complete email with real database operations.

        This test sends a full email through the SMTP server, exercising:
        - RCPT TO (lookup_recipient)
        - DATA (validate_email_auth, _process_and_persist_message)

        All of these involve database operations that will fail if the
        event loop issue is not fixed.
        """
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        email_content = b"""\
From: sender@external.com
To: user@real-test.example.com
Subject: Real Database Test
Message-ID: <real-db-test-001@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

This email tests the SMTP server with a real database.
"""

        errors, message = await smtp.sendmail(
            "sender@external.com",
            ["user@real-test.example.com"],
            email_content,
        )

        assert errors == {}, f"SMTP returned errors: {errors}"
        assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_concurrent_connections(
        self,
        smtp_server_real_db,
        smtp_settings: Settings,
    ):
        """Test multiple concurrent SMTP connections with real database.

        This test verifies that the UnthreadedController properly handles
        concurrent connections on the same event loop. Each connection
        performs database operations (RCPT TO lookup), ensuring the async
        database engine handles concurrent access correctly.
        """
        num_connections = 10

        async def send_email(connection_id: int) -> tuple[int, bool, str]:
            """Send an email and return (connection_id, success, message)."""
            try:
                smtp = aiosmtplib.SMTP(
                    hostname=smtp_settings.smtp_host,
                    port=smtp_settings.smtp_port,
                    timeout=30,
                )
                await smtp.connect()

                email_content = f"""\
From: sender{connection_id}@external.com
To: user@real-test.example.com
Subject: Concurrent Test {connection_id}
Message-ID: <concurrent-test-{connection_id:03d}@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

This is concurrent email number {connection_id}.
""".encode()

                errors, message = await smtp.sendmail(
                    f"sender{connection_id}@external.com",
                    ["user@real-test.example.com"],
                    email_content,
                )
                await smtp.quit()

                success = errors == {} and "accepted" in message.lower()
                return (connection_id, success, message if success else str(errors))
            except Exception as e:
                return (connection_id, False, str(e))

        # Launch all connections concurrently
        tasks = [send_email(i) for i in range(num_connections)]
        results = await asyncio.gather(*tasks)

        # Verify all connections succeeded
        failures = [(cid, msg) for cid, success, msg in results if not success]
        assert len(failures) == 0, f"Failed connections: {failures}"

        # Verify we got results from all connections
        assert len(results) == num_connections

    @pytest.mark.asyncio
    async def test_smtp_concurrent_rcpt_lookups(
        self,
        smtp_server_real_db,
        smtp_settings: Settings,
    ):
        """Test concurrent RCPT TO commands triggering database lookups.

        This test opens a single connection but sends multiple RCPT TO
        commands rapidly, testing concurrent database lookup operations.
        """
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()
        await smtp.ehlo()
        await smtp.mail("sender@external.com")

        # Send multiple RCPT TO commands (all to the same catch-all recipient)
        num_recipients = 5
        for i in range(num_recipients):
            response = await smtp.rcpt(f"user{i}@real-test.example.com")
            assert response.code == 250, f"RCPT {i} failed: {response.code} {response.message}"

        await smtp.rset()
        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_sustained_load(
        self,
        smtp_server_real_db,
        smtp_settings: Settings,
    ):
        """Test sustained load with multiple sequential emails over one connection.

        This verifies connection reuse works correctly with the async implementation.
        """
        smtp = aiosmtplib.SMTP(
            hostname=smtp_settings.smtp_host,
            port=smtp_settings.smtp_port,
        )
        await smtp.connect()

        num_emails = 20

        for i in range(num_emails):
            email_content = f"""\
From: sender@external.com
To: user@real-test.example.com
Subject: Sustained Load Test {i}
Message-ID: <sustained-load-{i:03d}@external.com>
Date: Mon, 1 Jan 2024 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Sustained load email number {i}.
""".encode()

            errors, message = await smtp.sendmail(
                "sender@external.com",
                ["user@real-test.example.com"],
                email_content,
            )
            assert errors == {}, f"Email {i} failed: {errors}"
            assert "accepted" in message.lower()

        await smtp.quit()

    @pytest.mark.asyncio
    async def test_smtp_mixed_concurrent_operations(
        self,
        smtp_server_real_db,
        smtp_settings: Settings,
    ):
        """Test mixed concurrent operations: some succeed, some fail (unknown domain).

        This ensures error handling works correctly under concurrent load.
        """
        num_connections = 6

        async def attempt_email(connection_id: int, should_succeed: bool) -> tuple[int, bool, str]:
            """Attempt to send email, expecting success or failure based on domain."""
            try:
                smtp = aiosmtplib.SMTP(
                    hostname=smtp_settings.smtp_host,
                    port=smtp_settings.smtp_port,
                    timeout=30,
                )
                await smtp.connect()
                await smtp.ehlo()
                await smtp.mail(f"sender{connection_id}@external.com")

                # Use valid or invalid domain based on should_succeed
                if should_succeed:
                    recipient = "user@real-test.example.com"
                else:
                    recipient = "user@unknown-domain.invalid"

                try:
                    response = await smtp.rcpt(recipient)
                    rcpt_succeeded = response.code == 250
                except aiosmtplib.SMTPRecipientRefused:
                    rcpt_succeeded = False

                await smtp.quit()

                # Check if result matches expectation
                if should_succeed:
                    return (
                        connection_id,
                        rcpt_succeeded,
                        "OK" if rcpt_succeeded else "Unexpected failure",
                    )
                else:
                    return (
                        connection_id,
                        not rcpt_succeeded,
                        "Correctly rejected" if not rcpt_succeeded else "Should have been rejected",
                    )

            except Exception as e:
                return (connection_id, False, str(e))

        # Launch mixed operations: half should succeed, half should fail
        tasks = [attempt_email(i, should_succeed=(i % 2 == 0)) for i in range(num_connections)]
        results = await asyncio.gather(*tasks)

        # All operations should have the expected outcome
        failures = [
            (cid, msg) for cid, matched_expectation, msg in results if not matched_expectation
        ]
        assert len(failures) == 0, f"Unexpected results: {failures}"
