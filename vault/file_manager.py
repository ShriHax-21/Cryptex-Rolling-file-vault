# vault/file_manager.py
# Handles file listing, deletion, and future vault file operations.
import os
try:
    from core.db import DB
except Exception:
    DB = None

VAULT_DIR = './storage/encrypted'


def _db():
    if DB is None:
        raise RuntimeError('Database not configured. Ensure core.db is importable and a DB backend is available.')
    try:
        d = DB()
        d.init_db()
        return d
    except Exception:
        raise


def list_vault_files():
    d = _db()
    return d.list_files()


def delete_vault_file(filename):
    d = _db()
    return d.delete_file_by_name(filename)


def store_vault_file(filename, content_bytes, nonce=None, iv=None, tag=None, alg=None, mode=None):
    d = _db()
    return d.store_file_blob(filename, content_bytes, nonce=nonce, iv=iv, tag=tag, alg=alg, mode=mode)


def get_vault_file(filename):
    d = _db()
    row = d.get_file_by_name(filename)
    return row


def store_vault_file_stream(src_path: str, dest_filename: str, key_manager, chunk_size: int = 4 * 1024 * 1024):
    """Encrypt a local file and place ciphertext file under storage dir.

    Writes ciphertext to `VAULT_DIR/dest_filename` and metadata alongside it.
    """
    from core import crypto_engine
    os.makedirs(VAULT_DIR, exist_ok=True)
    dest_path = os.path.join(VAULT_DIR, dest_filename)
    return crypto_engine.stream_encrypt_file(src_path, dest_path, key_manager, chunk_size=chunk_size)


def retrieve_vault_file_stream(stored_filename: str, out_path: str, key_manager):
    """Decrypt a stored streamed ciphertext under `VAULT_DIR` to `out_path`."""
    from core import crypto_engine
    src_path = os.path.join(VAULT_DIR, stored_filename)
    return crypto_engine.stream_decrypt_file(src_path, out_path, key_manager)
