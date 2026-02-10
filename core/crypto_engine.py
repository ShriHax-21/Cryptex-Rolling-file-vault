# crypto_engine.py
# Handles AES encryption/decryption for files

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct
import json
from typing import Optional
import os

class CryptoEngine:
    def __init__(self, key: bytes, mode=AES.MODE_GCM):
        self.key = key
        self.mode = mode

    def encrypt(self, data: bytes, nonce: Optional[bytes] = None) -> dict:
        # allow caller to supply a nonce to support deterministic per-chunk nonces
        if nonce is not None:
            cipher = AES.new(self.key, self.mode, nonce=nonce)
        else:
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


def _pack_counter(counter: int) -> bytes:
    return struct.pack('>I', counter)


def stream_encrypt_file(src_path: str, dest_path: str, key_manager, chunk_size: int = 4 * 1024 * 1024, format_version: int = 1, small_file_threshold: int = 1 * 1024 * 1024, simulate_stop_after: Optional[int] = None):
    """Encrypt a file in streaming, chunked AEAD mode with envelope-wrapped file key.

    - `key_manager` must implement `derive_key(salt: bytes) -> bytes`.
    - Writes ciphertext to `dest_path` (temporary .part during work) and metadata to `dest_path + .meta.json`.
    - Supports resume by loading existing metadata and continuing from last completed chunk.
    """
    total_size = os.path.getsize(src_path)
    meta_path = dest_path + '.meta.json'
    temp_dest = dest_path + '.part'

    # small-file fallback (keeps compatibility)
    if total_size <= small_file_threshold:
        # single-chunk behaviour: read whole file and encrypt in one call
        with open(src_path, 'rb') as f:
            plaintext = f.read()
        file_key = get_random_bytes(32)
        engine = CryptoEngine(file_key)
        enc = engine.encrypt(plaintext)
        # wrap file key with a KEK derived from a random salt
        kek_salt = get_random_bytes(16)
        kek = key_manager.derive_key(kek_salt)
        kek_cipher = AES.new(kek, AES.MODE_GCM)
        wrapped_key_ct, wrapped_key_tag = kek_cipher.encrypt_and_digest(file_key)
        wrapped = {
            'kek_salt': kek_salt.hex(),
            'ciphertext': wrapped_key_ct.hex(),
            'nonce': kek_cipher.nonce.hex(),
            'tag': wrapped_key_tag.hex()
        }
        # write ciphertext and metadata
        with open(temp_dest, 'wb') as out:
            out.write(enc['ciphertext'])
        metadata = {
            'format_version': format_version,
            'wrapped_file_key': wrapped,
            'file_base_nonce': enc['nonce'].hex(),
            'chunk_size': total_size,
            'chunks': [{
                'offset': 0,
                'length': len(enc['ciphertext']),
                'nonce': enc['nonce'].hex(),
                'tag': enc['tag'].hex()
            }],
            'total_plain_size': total_size,
            'state': 'completed'
        }
        # atomic metadata write
        with open(meta_path + '.tmp', 'w') as mf:
            json.dump(metadata, mf)
        os.replace(meta_path + '.tmp', meta_path)
        os.replace(temp_dest, dest_path)
        return metadata

    # For large files: chunked streaming
    base_nonce8 = get_random_bytes(8)
    # create a new random file key
    file_key = get_random_bytes(32)

    # wrap file key with KEK derived from random salt
    kek_salt = get_random_bytes(16)
    kek = key_manager.derive_key(kek_salt)
    kek_cipher = AES.new(kek, AES.MODE_GCM)
    wrapped_key_ct, wrapped_key_tag = kek_cipher.encrypt_and_digest(file_key)
    wrapped = {
        'kek_salt': kek_salt.hex(),
        'ciphertext': wrapped_key_ct.hex(),
        'nonce': kek_cipher.nonce.hex(),
        'tag': wrapped_key_tag.hex()
    }

    # load existing metadata if present to resume
    if os.path.exists(meta_path):
        try:
            with open(meta_path, 'r') as mf:
                metadata = json.load(mf)
        except Exception:
            metadata = None
    else:
        metadata = None

    chunks = []
    start_chunk = 0
    if metadata and metadata.get('format_version') == format_version:
        # resume
        chunks = metadata.get('chunks', [])
        start_chunk = len(chunks)
        base_nonce8 = bytes.fromhex(metadata.get('file_base_nonce')) if metadata.get('file_base_nonce') else base_nonce8

    # open files
    with open(src_path, 'rb') as src, open(temp_dest, 'ab') as out:
        # seek source to start_chunk
        src.seek(start_chunk * chunk_size)
        engine = CryptoEngine(file_key)
        chunk_index = start_chunk
        written_bytes = sum(c.get('length', 0) for c in chunks)
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            # prepare 12-byte nonce: 8-byte base + 4-byte counter
            nonce = base_nonce8 + _pack_counter(chunk_index)
            enc = engine.encrypt(chunk, nonce=nonce)
            out.write(enc['ciphertext'])
            chunks.append({
                'offset': chunk_index * chunk_size,
                'length': len(enc['ciphertext']),
                'nonce': enc['nonce'].hex(),
                'tag': enc['tag'].hex()
            })
            chunk_index += 1
            written_bytes += len(enc['ciphertext'])

            # update metadata atomically after each chunk
            metadata = {
                'format_version': format_version,
                'wrapped_file_key': wrapped,
                'file_base_nonce': base_nonce8.hex(),
                'chunk_size': chunk_size,
                'chunks': chunks,
                'total_plain_size': total_size,
                'state': 'incomplete'
            }
            with open(meta_path + '.tmp', 'w') as mf:
                json.dump(metadata, mf)
            os.replace(meta_path + '.tmp', meta_path)

            # optional testing hook to simulate interruption
            if simulate_stop_after is not None and chunk_index >= simulate_stop_after:
                return metadata

    # finalize
    metadata['state'] = 'completed'
    with open(meta_path + '.tmp', 'w') as mf:
        json.dump(metadata, mf)
    os.replace(meta_path + '.tmp', meta_path)
    os.replace(temp_dest, dest_path)
    return metadata


def stream_decrypt_file(src_path: str, dest_path: str, key_manager, format_version: int = 1):
    """Decrypt a streamed file using metadata in `src_path + .meta.json`.

    `key_manager` must implement `derive_key(salt: bytes) -> bytes`.
    """
    meta_path = src_path + '.meta.json'
    if not os.path.exists(meta_path):
        raise FileNotFoundError('Missing metadata file for streamed decrypt')
    with open(meta_path, 'r') as mf:
        metadata = json.load(mf)
    if metadata.get('format_version') != format_version:
        raise ValueError('Unsupported format version')

    wrapped = metadata['wrapped_file_key']
    kek_salt = bytes.fromhex(wrapped['kek_salt'])
    kek = key_manager.derive_key(kek_salt)
    kek_cipher = AES.new(kek, AES.MODE_GCM, nonce=bytes.fromhex(wrapped['nonce']))
    file_key = kek_cipher.decrypt_and_verify(bytes.fromhex(wrapped['ciphertext']), bytes.fromhex(wrapped['tag']))

    chunks = metadata.get('chunks', [])
    temp_out = dest_path + '.part'
    with open(src_path, 'rb') as src, open(temp_out, 'wb') as out:
        for c in chunks:
            length = c['length']
            nonce = bytes.fromhex(c['nonce'])
            tag = bytes.fromhex(c['tag'])
            # read ciphertext chunk sequentially
            ct = src.read(length)
            engine = CryptoEngine(file_key)
            # decrypt expects dict
            dec = engine.decrypt({'ciphertext': ct, 'nonce': nonce, 'tag': tag})
            out.write(dec)
    os.replace(temp_out, dest_path)
    return True
