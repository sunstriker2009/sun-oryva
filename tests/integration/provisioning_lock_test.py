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

    def test_lock_is_session_scoped_not_transaction_scoped(self):
        with psycopg.connect(DSN) as first, psycopg.connect(DSN) as second:
            self.assertTrue(first.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            first.commit()
            self.assertFalse(second.execute("SELECT pg_try_advisory_lock(%s)", (LOCK_KEY,)).fetchone()[0])
            self.assertTrue(first.execute("SELECT pg_advisory_unlock(%s)", (LOCK_KEY,)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
