from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
import json
import os
import threading
import time
from core.key_manager import KeyManager
from core.crypto_engine import CryptoEngine

VAULT_ID_PATH = os.path.join('storage', 'vault_id.bin')


class VaultSession:
    def __init__(self, master_secret: str, metadata_path: str = os.path.join('storage', 'metadata.json')):
        self.master_secret = master_secret
        self.metadata_path = metadata_path
        self.key_manager = KeyManager(self.master_secret, self.metadata_path)
        self.key = None
        self.key_salt = None
        self.crypto_engine = None
        self.unlocked = False
        self._auto_lock_timer = None
        self._lock_timeout = None

    def unlock(self):
        # If a password is already set in metadata, verify it first
        if KeyManager.password_is_set(self.metadata_path):
            if not self.key_manager.verify_password(self.master_secret):
                raise ValueError('Invalid vault password')

        key, salt = self.key_manager.get_latest_key()
        if key is None:
            # no key material yet, create fresh salt/key
            key, salt = self.key_manager.rotate_key()
        self.key = key
        self.key_salt = salt
        self.crypto_engine = CryptoEngine(self.key)
        # Ensure vault identity exists and is decryptable with this key
        if os.path.exists(VAULT_ID_PATH):
            try:
                with open(VAULT_ID_PATH, 'rb') as f:
                    blob = f.read()
                # try decrypting with AES-GCM using key
                # blob format: json({'nonce':..., 'ciphertext':..., 'tag':...})
                parts = json.loads(blob.decode())
                cipher = AES.new(self.key, AES.MODE_GCM, nonce=bytes.fromhex(parts.get('nonce', '')))
                cipher.decrypt_and_verify(bytes.fromhex(parts.get('ciphertext', '')), bytes.fromhex(parts.get('tag', '')))
            except Exception:
                # failed to decrypt vault id -> wrong password or corrupted vault id
                raise ValueError('Vault identity verification failed. Wrong password or vault mismatch.')
        else:
            # create vault id and write encrypted blob
            vid = get_random_bytes(32).hex()
            payload = json.dumps({'vault_id': vid}).encode()
            cipher = AES.new(self.key, AES.MODE_GCM)
            ct, tag = cipher.encrypt_and_digest(payload)
            blob = json.dumps({'nonce': cipher.nonce.hex(), 'ciphertext': ct.hex(), 'tag': tag.hex()}).encode()
            with open(VAULT_ID_PATH, 'wb') as f:
                f.write(blob)
        self.unlocked = True
        return True

    def lock(self):
        # wipe sensitive data
        self.key = None
        self.key_salt = None
        self.crypto_engine = None
        self.unlocked = False
        # cancel auto-lock timer
        if self._auto_lock_timer:
            self._auto_lock_timer.cancel()
            self._auto_lock_timer = None

    def start_auto_lock(self, timeout_seconds: int):
        self._lock_timeout = timeout_seconds
        if self._auto_lock_timer:
            self._auto_lock_timer.cancel()
        self._auto_lock_timer = threading.Timer(timeout_seconds, self.lock)
        self._auto_lock_timer.daemon = True
        self._auto_lock_timer.start()

    def reset_auto_lock(self):
        if self._lock_timeout:
            self.start_auto_lock(self._lock_timeout)

    def decrypt_in_memory(self, file_path: str, alg: str = None, mode: str = None):
        """Decrypt a vault file into memory and return (data_bytes, integrity_status)
        integrity_status: 'verified', 'failed', 'not_verified'
        """
        if not self.unlocked or self.key is None:
            raise ValueError('Vault is locked')
        with open(file_path, 'rb') as f:
            header = f.readline()
            try:
                enc_dict = json.loads(header.decode())
            except Exception:
                enc_dict = {}
            ciphertext = f.read()

        # Attempt to infer alg/mode from filename if not provided
        if not alg or not mode:
            base = os.path.basename(file_path)
            if base.endswith('.enc') and '.' in base[:-4]:
                parts = base[:-4].rsplit('.', 1)
                alg_mode = parts[-1]
                if '_' in alg_mode:
                    alg, mode = alg_mode.split('_', 1)
                    alg = alg.upper()
                    mode = mode.upper()
        # Default to AES if missing
        if not alg:
            alg = 'AES'
        if not mode:
            mode = 'GCM'

        try:
            if alg == 'AES':
                key = self.key[:32]
                cipher_mode = getattr(AES, f"MODE_{mode}")
                if mode == 'GCM':
                    cipher = AES.new(key, cipher_mode, nonce=bytes.fromhex(enc_dict.get('nonce', '')))
                    try:
                        dec = cipher.decrypt_and_verify(ciphertext, bytes.fromhex(enc_dict.get('tag', '')))
                        return dec, 'verified'
                    except Exception:
                        return b'', 'failed'
                elif mode == 'CBC':
                    cipher = AES.new(key, cipher_mode, iv=bytes.fromhex(enc_dict.get('iv', '')))
                    dec = cipher.decrypt(ciphertext)
                    # pkcs7 unpad
                    pad_len = dec[-1] if dec else 0
                    if pad_len and pad_len <= AES.block_size:
                        return dec[:-pad_len], 'not_verified'
                    return dec, 'not_verified'
                else:  # ECB
                    cipher = AES.new(key, cipher_mode)
                    dec = cipher.decrypt(ciphertext)
                    pad_len = dec[-1] if dec else 0
                    if pad_len and pad_len <= AES.block_size:
                        return dec[:-pad_len], 'not_verified'
                    return dec, 'not_verified'
            elif alg == 'DES':
                key = self.key[:8]
                cipher_mode = getattr(DES, f"MODE_{mode}")
                if mode == 'GCM':
                    return b'', 'failed'
                elif mode == 'CBC':
                    cipher = DES.new(key, cipher_mode, iv=bytes.fromhex(enc_dict.get('iv', '')))
                    dec = cipher.decrypt(ciphertext)
                    pad_len = dec[-1] if dec else 0
                    if pad_len and pad_len <= DES.block_size:
                        return dec[:-pad_len], 'not_verified'
                    return dec, 'not_verified'
                else:
                    cipher = DES.new(key, cipher_mode)
                    dec = cipher.decrypt(ciphertext)
                    pad_len = dec[-1] if dec else 0
                    if pad_len and pad_len <= DES.block_size:
                        return dec[:-pad_len], 'not_verified'
                    return dec, 'not_verified'
            elif alg in ('3DES', 'DES3'):
                key = self.key[:24]
                cipher_mode = getattr(DES3, f"MODE_{mode}")
                if mode == 'GCM':
                    return b'', 'failed'
                elif mode == 'CBC':
                    cipher = DES3.new(key, cipher_mode, iv=bytes.fromhex(enc_dict.get('iv', '')))
                    dec = cipher.decrypt(ciphertext)
                    pad_len = dec[-1] if dec else 0
                    if pad_len and pad_len <= DES3.block_size:
                        return dec[:-pad_len], 'not_verified'
                    return dec, 'not_verified'
                else:
                    cipher = DES3.new(key, cipher_mode)
                    dec = cipher.decrypt(ciphertext)
                    pad_len = dec[-1] if dec else 0
                    if pad_len and pad_len <= DES3.block_size:
                        return dec[:-pad_len], 'not_verified'
                    return dec, 'not_verified'
        except Exception:
            return b'', 'failed'

    def reset(self, wipe_storage: bool = True):
        """Reset the vault by wiping metadata, vault id, and optional storage folders.

        WARNING: This permanently deletes encrypted data and metadata.
        """
        # Ensure any in-memory secrets are wiped
        self.lock()

        # Remove metadata file
        try:
            if os.path.exists(self.metadata_path):
                os.remove(self.metadata_path)
        except Exception:
            pass

        # Remove vault identity
        try:
            if os.path.exists(VAULT_ID_PATH):
                os.remove(VAULT_ID_PATH)
        except Exception:
            pass

        if wipe_storage:
            # Wipe encrypted and decrypted storage directories
            for d in (os.path.join('storage', 'encrypted'), os.path.join('storage', 'decrypted')):
                try:
                    if os.path.isdir(d):
                        for root, dirs, files in os.walk(d):
                            for name in files:
                                try:
                                    os.remove(os.path.join(root, name))
                                except Exception:
                                    pass
                            for name in dirs:
                                try:
                                    os.rmdir(os.path.join(root, name))
                                except Exception:
                                    pass
                        try:
                            os.rmdir(d)
                        except Exception:
                            pass
                except Exception:
                    pass

        return True
