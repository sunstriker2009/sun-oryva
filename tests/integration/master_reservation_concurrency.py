"""PostgreSQL concurrency and restart safety tests for ORYVA master reservations.

Run with ORYVA_TEST_DATABASE_URL pointing to an isolated disposable database.
Requires psycopg 3: pip install 'psycopg[binary]>=3.2,<4'
"""
import concurrent.futures
import os
import unittest

import psycopg


DSN = os.environ.get("ORYVA_TEST_DATABASE_URL")


@unittest.skipUnless(DSN, "Set ORYVA_TEST_DATABASE_URL to a disposable test database")
class MasterReservationConcurrencyTests(unittest.TestCase):
    def setUp(self):
        with psycopg.connect(DSN) as conn:
            conn.execute("TRUNCATE TABLE oryva.master_bootstrap")

    @staticmethod
    def reserve():
        with psycopg.connect(DSN) as conn:
            with conn.transaction():
                conn.execute(
                    "INSERT INTO oryva.master_bootstrap (singleton_id, state) "
                    "VALUES (1, 'pending') ON CONFLICT (singleton_id) DO NOTHING"
                )
                return conn.execute(
                    "SELECT state FROM oryva.master_bootstrap WHERE singleton_id = 1 FOR UPDATE"
                ).fetchone()[0]

    def test_parallel_reservations_create_exactly_one_pending_row(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: self.reserve(), range(36)))
        self.assertEqual(results, ["pending"] * 36)
        with psycopg.connect(DSN) as conn:
            self.assertEqual(
                conn.execute("SELECT count(*) FROM oryva.master_bootstrap").fetchone()[0],
                1,
            )

    def test_pending_reservation_survives_reconnect(self):
        self.assertEqual(self.reserve(), "pending")
        self.assertEqual(self.reserve(), "pending")
        with psycopg.connect(DSN) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT state, subject_id FROM oryva.master_bootstrap WHERE singleton_id=1"
                ).fetchone(),
                ("pending", None),
            )

    def test_conflicting_activation_is_rejected(self):
        self.reserve()
        with psycopg.connect(DSN) as conn:
            conn.execute(
                "UPDATE oryva.master_bootstrap SET state='active', "
                "subject_id='master-a', activated_at=now() WHERE singleton_id=1"
            )
        with psycopg.connect(DSN) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT subject_id FROM oryva.master_bootstrap "
                    "WHERE singleton_id=1 AND state='active'"
                ).fetchone()[0],
                "master-a",
            )
            with self.assertRaises(psycopg.errors.CheckViolation):
                conn.execute(
                    "INSERT INTO oryva.master_bootstrap (singleton_id, state) "
                    "VALUES (2, 'pending')"
                )


if __name__ == "__main__":
    unittest.main()
