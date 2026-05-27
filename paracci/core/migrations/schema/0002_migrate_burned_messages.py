# -*- coding: utf-8 -*-
from yoyo import step

def migrate_burned_messages(conn):
    # Check if the status column exists
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(burned_messages)")
    columns = {row[1] for row in cursor.fetchall()}
    if "status" not in columns:
        cursor.execute("ALTER TABLE burned_messages RENAME TO burned_messages_legacy")
        cursor.execute("""
            CREATE TABLE burned_messages (
                fingerprint     BLOB PRIMARY KEY,
                status          BLOB NOT NULL,
                reserved_at     BLOB NOT NULL,
                burned_at       BLOB,
                failed_at       BLOB,
                session_id      BLOB,
                direction       BLOB,
                failure_reason  BLOB
            )
        """)
        cursor.execute(
            """
            INSERT OR IGNORE INTO burned_messages
                (fingerprint, status, reserved_at, burned_at, failed_at, session_id, direction, failure_reason)
            SELECT
                fingerprint, ?, burned_at, burned_at, NULL, session_id, direction, NULL
            FROM burned_messages_legacy
            """,
            ("burned",),
        )
        cursor.execute("DROP TABLE burned_messages_legacy")

steps = [
    step(migrate_burned_messages)
]
