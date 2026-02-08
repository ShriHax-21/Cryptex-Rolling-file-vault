#!/usr/bin/env python3
"""Change vault password by migrating encrypted blobs from stored key to new password-derived key.

WARNING: This script uses the stored derived key material in `storage/metadata.json` to decrypt
existing data. It then re-encrypts vault identity and all files under `storage/encrypted` with
the new password-derived key and updates `storage/metadata.json` accordingly.

Run from repo root: python3 scripts/change_password.py --new-password hello
"""

import os
import sys
import json
import argparse

# Ensure project root is on sys.path so `from core.db import DB` works
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from core.db import DB



def backup_storage(backup_dir):
    # No filesystem storage in DB-only mode; keep placeholder for compatibility
    os.makedirs(backup_dir, exist_ok=True)


def pkcs7_pad(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError('Invalid padding')
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError('Invalid padding content')
    return data[:-pad_len]


def decrypt_blob_with_key(enc_dict, ciphertext, key, alg='AES', mode='GCM'):
    try:
        if alg == 'AES':
            k = key[:32]
            if mode == 'GCM':
                cipher = AES.new(k, AES.MODE_GCM, nonce=bytes.fromhex(enc_dict.get('nonce', '')))
                return cipher.decrypt_and_verify(ciphertext, bytes.fromhex(enc_dict.get('tag', '')))
            elif mode == 'CBC':
                cipher = AES.new(k, AES.MODE_CBC, iv=bytes.fromhex(enc_dict.get('iv', '')))
                return pkcs7_unpad(cipher.decrypt(ciphertext))
            else:
                cipher = AES.new(k, AES.MODE_ECB)
                return pkcs7_unpad(cipher.decrypt(ciphertext))
        elif alg == 'DES':
            k = key[:8]
            if mode == 'CBC':
                cipher = DES.new(k, DES.MODE_CBC, iv=bytes.fromhex(enc_dict.get('iv', '')))
                return pkcs7_unpad(cipher.decrypt(ciphertext))
            else:
                cipher = DES.new(k, DES.MODE_ECB)
                return pkcs7_unpad(cipher.decrypt(ciphertext))
        elif alg in ('3DES', 'DES3'):
            k = key[:24]
            if mode == 'CBC':
                cipher = DES3.new(k, DES3.MODE_CBC, iv=bytes.fromhex(enc_dict.get('iv', '')))
                return pkcs7_unpad(cipher.decrypt(ciphertext))
            else:
                cipher = DES3.new(k, DES3.MODE_ECB)
                return pkcs7_unpad(cipher.decrypt(ciphertext))
    except Exception:
        raise


def encrypt_blob_with_key(plaintext, key, alg='AES', mode='GCM'):
    if alg == 'AES':
        k = key[:32]
        if mode == 'GCM':
            cipher = AES.new(k, AES.MODE_GCM)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            return {'nonce': cipher.nonce.hex(), 'ciphertext': ct.hex(), 'tag': tag.hex()}, ct
        elif mode == 'CBC':
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(k, AES.MODE_CBC, iv=iv)
            pt = pkcs7_pad(plaintext, AES.block_size)
            ct = cipher.encrypt(pt)
            return {'iv': iv.hex(), 'ciphertext': ct.hex(), 'tag': ''}, ct
        else:
            cipher = AES.new(k, AES.MODE_ECB)
            pt = pkcs7_pad(plaintext, AES.block_size)
            ct = cipher.encrypt(pt)
            return {'ciphertext': ct.hex(), 'tag': ''}, ct
    elif alg == 'DES':
        k = key[:8]
        if mode == 'CBC':
            iv = get_random_bytes(DES.block_size)
            cipher = DES.new(k, DES.MODE_CBC, iv=iv)
            pt = pkcs7_pad(plaintext, DES.block_size)
            ct = cipher.encrypt(pt)
            return {'iv': iv.hex(), 'ciphertext': ct.hex(), 'tag': ''}, ct
        else:
            cipher = DES.new(k, DES.MODE_ECB)
            pt = pkcs7_pad(plaintext, DES.block_size)
            ct = cipher.encrypt(pt)
            return {'ciphertext': ct.hex(), 'tag': ''}, ct
    else:
        k = key[:24]
        if mode == 'CBC':
            iv = get_random_bytes(DES3.block_size)
            cipher = DES3.new(k, DES3.MODE_CBC, iv=iv)
            pt = pkcs7_pad(plaintext, DES3.block_size)
            ct = cipher.encrypt(pt)
            return {'iv': iv.hex(), 'ciphertext': ct.hex(), 'tag': ''}, ct
        else:
            cipher = DES3.new(k, DES3.MODE_ECB)
            pt = pkcs7_pad(plaintext, DES3.block_size)
            ct = cipher.encrypt(pt)
            return {'ciphertext': ct.hex(), 'tag': ''}, ct


def infer_alg_mode_from_filename(fname):
    base = os.path.basename(fname)
    alg = 'AES'
    mode = 'GCM'
    if base.endswith('.enc') and '.' in base[:-4]:
        parts = base[:-4].rsplit('.', 1)
        alg_mode = parts[-1]
        if '_' in alg_mode:
            a, m = alg_mode.split('_', 1)
            return a.upper(), m.upper()
    return alg, mode


def migrate(db: DB, new_password, iterations=200000):
    # find latest stored key material
    latest = db.get_latest_key()
    if not latest or 'key_hex' not in latest:
        raise RuntimeError('No stored derived keys found in DB; cannot migrate without original key.')
    old_key = bytes.fromhex(latest['key_hex'])

    # vault_id stored in meta table (if present)
    payload = None
    vault_meta = db.get_meta('vault_id')
    if vault_meta:
        try:
            meta_obj = json.loads(vault_meta)
            payload = decrypt_blob_with_key(meta_obj, bytes.fromhex(meta_obj.get('ciphertext', '')), old_key, alg='AES', mode='GCM')
            print('Decrypted existing vault_id using stored key')
        except Exception as e:
            print('Warning: failed to decrypt existing vault_id with stored key:', e)
            payload = None

    if payload is None:
        print('Initializing new vault id (existing vault_id not recoverable)')
        payload = json.dumps({'vault_id': os.urandom(16).hex()}).encode()

    # derive new key and password verifier
    new_salt = get_random_bytes(16)
    new_key = pbkdf2_hmac('sha256', new_password.encode(), new_salt, iterations, dklen=32)
    new_pwd_dk = pbkdf2_hmac('sha256', new_password.encode(), new_salt, iterations, dklen=32)

    # re-encrypt vault_id with new key and store in meta
    enc_meta, ct = encrypt_blob_with_key(payload, new_key, alg='AES', mode='GCM')
    db.set_meta('vault_id', json.dumps(enc_meta))
    print('Re-encrypted vault_id with new password-derived key (stored in DB)')

    # re-encrypt all files in DB
    files = db.list_files()
    for name in files:
        try:
            row = db.get_file_by_name(name)
            if not row or not row.get('content'):
                continue
            content = row.get('content')
            if isinstance(content, memoryview):
                content = bytes(content)
            parts = content.split(b'\n', 1)
            header = parts[0] if parts else b'{}'
            try:
                enc_dict = json.loads(header.decode())
            except Exception:
                enc_dict = {}
            ciphertext = parts[1] if len(parts) > 1 else b''
            alg, mode = infer_alg_mode_from_filename(name)
            try:
                plain = decrypt_blob_with_key(enc_dict, ciphertext, old_key, alg=alg, mode=mode)
            except Exception as e:
                print('Skipping file (decrypt failed):', name, e)
                continue
            new_enc_meta, new_ct = encrypt_blob_with_key(plain, new_key, alg=alg, mode=mode)
            new_content = json.dumps(new_enc_meta).encode() + b"\n" + new_ct
            db.store_file_blob(name, new_content, nonce=new_enc_meta.get('nonce'), iv=new_enc_meta.get('iv'), tag=new_enc_meta.get('tag'), alg=alg, mode=mode)
            print('Migrated file in DB:', name)
        except Exception as e:
            print('Error migrating file', name, e)

    # update keys and password meta in DB
    db.store_key(new_salt.hex(), new_key.hex())
    db.set_password_meta(new_salt.hex(), new_pwd_dk.hex(), iterations)
    print('Updated DB with new password verifier and derived key')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--new-password', required=True)
    parser.add_argument('--db', default=os.getenv('SQLITE_DB_PATH', 'vault.db'))
    args = parser.parse_args()

    db = DB(db_path=args.db)
    db.init_db()
    migrate(db, args.new_password)


if __name__ == '__main__':
    main()
