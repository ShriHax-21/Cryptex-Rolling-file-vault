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
