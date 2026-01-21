# crypto_engine.py
# Handles AES encryption/decryption for files

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

class CryptoEngine:
    def __init__(self, key: bytes, mode=AES.MODE_GCM):
        self.key = key
        self.mode = mode

    def encrypt(self, data: bytes) -> dict:
        cipher = AES.new(self.key, self.mode)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return {
            'ciphertext': ciphertext,
            'nonce': cipher.nonce,
            'tag': tag
        }

    def decrypt(self, enc_dict: dict) -> bytes:
        cipher = AES.new(self.key, self.mode, nonce=enc_dict['nonce'])
        return cipher.decrypt_and_verify(enc_dict['ciphertext'], enc_dict['tag'])
