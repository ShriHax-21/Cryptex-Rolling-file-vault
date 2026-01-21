# integrity.py
# Handles file integrity verification (SHA-256, HMAC optional)

import hashlib
import hmac

class Integrity:
    @staticmethod
    def sha256_digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def hmac_sha256(key: bytes, data: bytes) -> str:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
