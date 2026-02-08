# key_manager.py
# Handles key derivation, storage, and rotation

import os
import json
import hmac
from hashlib import pbkdf2_hmac
from Crypto.Random import get_random_bytes
from typing import Optional

try:
    from core.db import DB
except Exception:
    DB = None


class KeyManager:
    """Handles password hashing, key derivation and simple key rotation.

    Passwords are stored as PBKDF2-HMAC-SHA256(hash) with a per-password salt
    and iteration count. Encryption keys are derived with PBKDF2 using the
    user-supplied master password and a per-key random salt.
    """

    DEFAULT_ITERATIONS = 200_000

    def __init__(self, master_secret: str, metadata_path: str, db: Optional[DB] = None):
        self.master_secret = master_secret
        self.metadata_path = metadata_path
        self.db = db
        self.metadata = self._load_metadata()
        self.keys = self.metadata.get('keys', {}) if isinstance(self.metadata, dict) else {}

    @staticmethod
    def password_is_set(metadata_path: str, db: Optional[DB] = None) -> bool:
        # If DB provided, check DB first
        if db is not None:
            try:
                pwd = db.get_password_meta()
                return bool(pwd)
            except Exception:
                return False
        if not os.path.exists(metadata_path):
            return False
        try:
            with open(metadata_path, 'r') as f:
                data = json.load(f)
            return 'password' in data
        except Exception:
            return False

    def _load_metadata(self) -> dict:
        # prefer DB if available
        if self.db is not None:
            try:
                pwd = self.db.get_password_meta()
                keys = self.db.get_keys()
                meta = {}
                if pwd:
                    meta['password'] = {'salt': pwd.get('salt'), 'hash': pwd.get('hash'), 'iterations': int(pwd.get('iterations', self.DEFAULT_ITERATIONS))}
                meta['keys'] = keys
                return meta
            except Exception:
                return {}
        if os.path.exists(self.metadata_path):
            try:
                with open(self.metadata_path, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_metadata(self):
        # persist to DB if available, otherwise file
        if self.db is not None:
            # store keys
            for salt, key_hex in self.keys.items():
                try:
                    self.db.store_key(salt, key_hex)
                except Exception:
                    pass
            # password saved elsewhere when set_password called
            return
        # ensure keys field exists
        self.metadata['keys'] = self.keys
        with open(self.metadata_path, 'w') as f:
            json.dump(self.metadata, f)

    def set_password(self, password: str) -> None:
        salt = get_random_bytes(16)
        iterations = self.DEFAULT_ITERATIONS
        dk = pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
        if self.db is not None:
            try:
                self.db.set_password_meta(salt.hex(), dk.hex(), iterations)
            except Exception:
                # fallback to file
                self.metadata['password'] = {'salt': salt.hex(), 'hash': dk.hex(), 'iterations': iterations}
                self._save_metadata()
            return
        self.metadata['password'] = {
            'salt': salt.hex(),
            'hash': dk.hex(),
            'iterations': iterations
        }
        self._save_metadata()

    def verify_password(self, password: str) -> bool:
        # load from DB if available
        if self.db is not None:
            try:
                pwd = self.db.get_password_meta()
                if not pwd:
                    return False
                salt = bytes.fromhex(pwd.get('salt', ''))
                iterations = int(pwd.get('iterations', self.DEFAULT_ITERATIONS))
                expected = bytes.fromhex(pwd.get('hash', ''))
                dk = pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=len(expected))
                return hmac.compare_digest(dk, expected)
            except Exception:
                return False
        pwd = self.metadata.get('password')
        if not pwd:
            return False
        salt = bytes.fromhex(pwd.get('salt', ''))
        iterations = int(pwd.get('iterations', self.DEFAULT_ITERATIONS))
        expected = bytes.fromhex(pwd.get('hash', ''))
        dk = pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=len(expected))
        return hmac.compare_digest(dk, expected)

    def derive_key(self, salt: bytes) -> bytes:
        # use PBKDF2 with same iteration count as the stored password to derive keys
        pwd_meta = self.metadata.get('password', {})
        iterations = int(pwd_meta.get('iterations', self.DEFAULT_ITERATIONS))
        if not self.master_secret:
            raise ValueError('No master secret available for key derivation')
        return pbkdf2_hmac('sha256', self.master_secret.encode(), salt, iterations, dklen=32)

    def rotate_key(self):
        salt = get_random_bytes(16)
        new_key = self.derive_key(salt)
        if self.db is not None:
            try:
                self.db.store_key(salt.hex(), new_key.hex())
            except Exception:
                # fallback: keep in memory and save to file
                self.keys[salt.hex()] = new_key.hex()
                self._save_metadata()
        else:
            self.keys[salt.hex()] = new_key.hex()
            self._save_metadata()
        return new_key, salt

    def get_latest_key(self):
        if self.db is not None:
            try:
                row = self.db.get_latest_key()
                if not row:
                    return None, None
                return bytes.fromhex(row.get('key_hex')), bytes.fromhex(row.get('salt'))
            except Exception:
                pass
        if not self.keys:
            return None, None
        latest_salt = list(self.keys.keys())[-1]
        return bytes.fromhex(self.keys[latest_salt]), bytes.fromhex(latest_salt)
