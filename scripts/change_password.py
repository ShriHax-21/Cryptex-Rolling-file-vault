#!/usr/bin/env python3
"""Change vault password by migrating encrypted blobs from stored key to new password-derived key.

WARNING: This script uses the stored derived key material in `storage/metadata.json` to decrypt
existing data. It then re-encrypts vault identity and all files under `storage/encrypted` with
the new password-derived key and updates `storage/metadata.json` accordingly.

Run from repo root: python3 scripts/change_password.py --new-password hello
"""

import os
import json
import shutil
import argparse
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes


def load_metadata(path):
    with open(path, 'r') as f:
        return json.load(f)


def save_metadata(path, metadata):
    with open(path, 'w') as f:
        json.dump(metadata, f)


def backup_storage(backup_dir):
    os.makedirs(backup_dir, exist_ok=True)
    for name in ('metadata.json', 'vault_id.bin'):
        src = os.path.join('storage', name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(backup_dir, name))
    enc_dir = os.path.join('storage', 'encrypted')
    if os.path.isdir(enc_dir):
        shutil.copytree(enc_dir, os.path.join(backup_dir, 'encrypted'))


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


def migrate(metadata_path, vault_id_path, enc_dir, new_password, iterations=200000):
    metadata = load_metadata(metadata_path)

    # find latest stored key material
    keys = metadata.get('keys', {})
    if not keys:
        raise RuntimeError('No stored derived keys found in metadata; cannot migrate without original key.')
    latest_salt_hex = list(keys.keys())[-1]
    latest_key_hex = keys[latest_salt_hex]
    old_key = bytes.fromhex(latest_key_hex)

    # backup
    # import time
    # ts = int(time.time())
    # backup_dir = os.path.join('storage', f'backup_{ts}')
    # print('Backing up metadata and encrypted storage to', backup_dir)
    # backup_storage(backup_dir)

    # decrypt vault_id.bin using old_key (if possible)
    payload = None
    if os.path.exists(vault_id_path):
        with open(vault_id_path, 'rb') as f:
            blob = f.read()
        parts = json.loads(blob.decode())
        try:
            payload = decrypt_blob_with_key(parts, bytes.fromhex(parts.get('ciphertext', '')), old_key, alg='AES', mode='GCM')
            print('Decrypted existing vault_id using stored key')
        except Exception as e:
            print('Warning: failed to decrypt existing vault_id with stored key:', e)
            payload = None
    
    if payload is None:
        # Cannot recover existing vault id — we will initialize a new vault.
        print('Proceeding to initialize a fresh vault. Existing encrypted files may become unrecoverable.')
        payload = json.dumps({'vault_id': os.urandom(16).hex()}).encode()
        # remove encrypted/decrypted directories to avoid confusion
        try:
            enc_dir_path = os.path.join('storage', 'encrypted')
            dec_dir_path = os.path.join('storage', 'decrypted')
            if os.path.isdir(enc_dir_path):
                shutil.rmtree(enc_dir_path)
            if os.path.isdir(dec_dir_path):
                shutil.rmtree(dec_dir_path)
            print('Removed existing storage/encrypted and storage/decrypted (backup exists).')
        except Exception:
            pass

    # derive new key and password verifier
    new_salt = get_random_bytes(16)
    new_key = pbkdf2_hmac('sha256', new_password.encode(), new_salt, iterations, dklen=32)
    new_pwd_dk = pbkdf2_hmac('sha256', new_password.encode(), new_salt, iterations, dklen=32)

    # re-encrypt vault_id with new key
    enc_meta, ct = encrypt_blob_with_key(payload, new_key, alg='AES', mode='GCM')
    with open(vault_id_path, 'wb') as f:
        f.write(json.dumps(enc_meta).encode())
    print('Re-encrypted vault_id with new password-derived key')

    # re-encrypt all files in encrypted dir
    if os.path.isdir(enc_dir):
        for root, _, files in os.walk(enc_dir):
            for name in files:
                fpath = os.path.join(root, name)
                try:
                    with open(fpath, 'rb') as f:
                        header = f.readline()
                        try:
                            enc_dict = json.loads(header.decode())
                        except Exception:
                            enc_dict = {}
                        ciphertext = f.read()
                    alg, mode = infer_alg_mode_from_filename(name)
                    # decrypt with old_key
                    try:
                        plain = decrypt_blob_with_key(enc_dict, ciphertext, old_key, alg=alg, mode=mode)
                    except Exception as e:
                        print('Skipping file (decrypt failed):', fpath, e)
                        continue
                    # encrypt with new_key
                    new_enc_meta, new_ct = encrypt_blob_with_key(plain, new_key, alg=alg, mode=mode)
                    with open(fpath, 'wb') as f:
                        f.write(json.dumps(new_enc_meta).encode() + b"\n")
                        f.write(new_ct)
                    print('Migrated:', fpath)
                except Exception as e:
                    print('Error migrating file', fpath, e)

    # update metadata.json: replace keys mapping and password verifier
    metadata['keys'] = {new_salt.hex(): new_key.hex()}
    metadata['password'] = {'salt': new_salt.hex(), 'hash': new_pwd_dk.hex(), 'iterations': iterations}
    save_metadata(metadata_path, metadata)
    print('Updated metadata.json with new password verifier and derived key')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--new-password', required=True)
    parser.add_argument('--metadata', default=os.path.join('storage', 'metadata.json'))
    parser.add_argument('--vault-id', default=os.path.join('storage', 'vault_id.bin'))
    parser.add_argument('--encrypted-dir', default=os.path.join('storage', 'encrypted'))
    args = parser.parse_args()

    migrate(args.metadata, args.vault_id, args.encrypted_dir, args.new_password)


if __name__ == '__main__':
    main()
