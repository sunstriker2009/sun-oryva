"""Integration tests for PostgreSQL session advisory-lock semantics.

Uses the same fixed key as Sun.Security.Bootstrap.MasterProvisioningLock.
Set ORYVA_TEST_DATABASE_URL to a disposable PostgreSQL instance.
"""
import os
import unittest
import psycopg

DSN = os.getenv("ORYVA_TEST_DATABASE_URL")
LOCK_KEY = 0x4F525956414D5354


@unittest.skipUnless(DSN, "Requires isolated PostgreSQL test database")
class ProvisioningLockTests(unittest.TestCase):
    def test_second_session_cannot_acquire_while_first_owns_lock(self):
        with psycopg.connect(DSN) as first, psycopg.connect(DSN) as second:
            self.assertTrue(first.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertFalse(second.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertTrue(first.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertTrue(second.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertTrue(second.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,)).fetchone()[0])

    def test_session_close_releases_lock(self):
        first = psycopg.connect(DSN)
        try:
            self.assertTrue(first.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            with psycopg.connect(DSN) as second:
                self.assertFalse(second.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            first.close()
            with psycopg.connect(DSN) as replacement:
                self.assertTrue(replacement.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
                self.assertTrue(replacement.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,)).fetchone()[0])
        finally:
            first.close()

    @staticmethod
    def session_holds_lock(connection):
        high = (LOCK_KEY >> 32) & 0xFFFFFFFF
        low = LOCK_KEY & 0xFFFFFFFF
        return connection.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM pg_locks
                WHERE locktype = 'advisory'
                  AND pid = pg_backend_pid()
                  AND granted
                  AND classid::bigint = %s
                  AND objid::bigint = %s
                  AND objsubid = 1
            )
            """,
            (high, low),
        ).fetchone()[0]

    def test_lock_continuity_matches_actual_session_ownership(self):
        with psycopg.connect(DSN) as owner, psycopg.connect(DSN) as observer:
            self.assertFalse(self.session_holds_lock(owner))
            self.assertFalse(self.session_holds_lock(observer))
            self.assertTrue(owner.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertTrue(self.session_holds_lock(owner))
            self.assertFalse(self.session_holds_lock(observer))
            owner.commit()
            self.assertTrue(self.session_holds_lock(owner))
            self.assertTrue(owner.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertFalse(self.session_holds_lock(owner))

    def test_continuity_fails_after_session_lock_is_released(self):
        with psycopg.connect(DSN) as owner:
            self.assertTrue(owner.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertTrue(self.session_holds_lock(owner))
            owner.execute("SELECT pg_advisory_unlock_all()")
            self.assertFalse(self.session_holds_lock(owner))

    def test_lock_is_session_scoped_not_transaction_scoped(self):
        with psycopg.connect(DSN) as first, psycopg.connect(DSN) as second:
            self.assertTrue(first.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            first.commit()
            self.assertFalse(second.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertTrue(first.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
