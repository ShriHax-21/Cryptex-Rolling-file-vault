# key_manager.py
# Handles key derivation, storage, and rotation

import os
import json
from hashlib import sha256
from Crypto.Random import get_random_bytes

class KeyManager:
    def __init__(self, master_secret: str, metadata_path: str):
        self.master_secret = master_secret
        self.metadata_path = metadata_path
        self.keys = self.load_keys()

    def derive_key(self, salt: bytes) -> bytes:
        return sha256(self.master_secret.encode() + salt).digest()

    def load_keys(self):
        if os.path.exists(self.metadata_path):
            with open(self.metadata_path, 'r') as f:
                return json.load(f).get('keys', {})
        return {}

    def save_keys(self):
        with open(self.metadata_path, 'w') as f:
            json.dump({'keys': self.keys}, f)

    def rotate_key(self):
        salt = get_random_bytes(16)
        new_key = self.derive_key(salt)
        self.keys[salt.hex()] = new_key.hex()
        self.save_keys()
        return new_key, salt

    def get_latest_key(self):
        if not self.keys:
            return None, None
        latest_salt = list(self.keys.keys())[-1]
        return bytes.fromhex(self.keys[latest_salt]), bytes.fromhex(latest_salt)
