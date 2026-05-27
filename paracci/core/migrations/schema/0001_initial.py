# -*- coding: utf-8 -*-
from yoyo import step

__depends__ = {}

steps = [
    step(
        """
        CREATE TABLE IF NOT EXISTS burned_messages (
            fingerprint     BLOB PRIMARY KEY,   -- SHA3-256(msg_id)
            burned_at       BLOB,               -- Unix timestamp
            session_id      BLOB,               -- Which session it belongs to
            direction       BLOB                -- 1=X→Y, 2=Y→X
        );
        """
    ),
    step(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id      BLOB PRIMARY KEY,   -- 16 bytes
            label           BLOB NOT NULL,
            state           BLOB NOT NULL,
            encrypted_meta  BLOB NOT NULL,      -- serialize_session_meta output
            created_at      BLOB NOT NULL,
            updated_at      BLOB NOT NULL
        );
        """
    ),
    step(
        """
        CREATE TABLE IF NOT EXISTS device_meta (
            key             TEXT PRIMARY KEY,
            value           BLOB NOT NULL
        );
        """
    ),
    step(
        """
        CREATE TABLE IF NOT EXISTS burn_internal_meta (
            key             TEXT PRIMARY KEY,
            value           BLOB NOT NULL
        );
        """
    ),
    step(
        """
        CREATE TABLE IF NOT EXISTS pending_deletions (
            file_path       TEXT PRIMARY KEY
        );
        """
    ),
]
