# core/db.py
# SQLite helper for storing vault metadata (password, keys, file metadata) in a single-file DB.
import os
import sqlite3
from contextlib import contextmanager


class DB:
    """SQLite-backed DB stored in a single file (default vault.db).

    The DB path can be set via the `SQLITE_DB_PATH` environment variable.
    """

    def __init__(self, db_path=None):
        self.db_path = db_path or os.getenv('SQLITE_DB_PATH', 'vault.db')

    @contextmanager
    def connect(self):
        need_init = not os.path.exists(self.db_path)
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def init_db(self):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE IF NOT EXISTS password_meta (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                salt TEXT,
                hash TEXT,
                iterations INTEGER
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                salt TEXT UNIQUE,
                key_hex TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT UNIQUE,
                path TEXT,
                content BLOB,
                nonce TEXT,
                iv TEXT,
                tag TEXT,
                alg TEXT,
                mode TEXT,
                size INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """)
            conn.commit()

    # Password meta helpers
    def get_password_meta(self):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT salt, hash, iterations FROM password_meta ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            return dict(row) if row else None

    def set_password_meta(self, salt, hash_hex, iterations):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO password_meta (salt, hash, iterations) VALUES (?,?,?)",
                        (salt, hash_hex, iterations))
            conn.commit()

    # Key helpers
    def get_keys(self):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT salt, key_hex FROM keys ORDER BY id ASC")
            rows = cur.fetchall()
            return {r['salt']: r['key_hex'] for r in rows} if rows else {}

    def store_key(self, salt, key_hex):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("INSERT OR IGNORE INTO keys (salt, key_hex) VALUES (?,?)", (salt, key_hex))
            conn.commit()

    def get_latest_key(self):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT salt, key_hex FROM keys ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            return dict(row) if row else None

    # File blob helpers
    def store_file_blob(self, filename, content_bytes, nonce=None, iv=None, tag=None, alg=None, mode=None):
        with self.connect() as conn:
            cur = conn.cursor()
            # Use INSERT OR REPLACE to upsert by filename
            cur.execute("""
            INSERT INTO files (filename, path, content, nonce, iv, tag, alg, mode, size)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(filename) DO UPDATE SET
                content=excluded.content, nonce=excluded.nonce, iv=excluded.iv, tag=excluded.tag, alg=excluded.alg, mode=excluded.mode, size=excluded.size
            ;
            """,
                        (filename, filename, content_bytes, nonce, iv, tag, alg, mode, len(content_bytes) if content_bytes is not None else None))
            conn.commit()

    def get_file_by_name(self, filename):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM files WHERE filename=? LIMIT 1", (filename,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_files(self):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT filename FROM files ORDER BY created_at DESC")
            rows = cur.fetchall()
            return [r['filename'] for r in rows] if rows else []

    def delete_file_by_name(self, filename):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM files WHERE filename=?", (filename,))
            conn.commit()

    def delete_all_files(self):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM files")
            conn.commit()

    # File metadata helper (minimal)
    def store_file_meta(self, filename, path, nonce=None, iv=None, tag=None, alg=None, mode=None, size=None):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO files (filename, path, nonce, iv, tag, alg, mode, size) VALUES (?,?,?,?,?,?,?,?)",
                (filename, path, nonce, iv, tag, alg, mode, size))
            conn.commit()

    # Simple key/value metadata
    def set_meta(self, key, value):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)", (key, value))
            conn.commit()

    def get_meta(self, key):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT value FROM meta WHERE key=?", (key,))
            row = cur.fetchone()
            return row[0] if row else None
