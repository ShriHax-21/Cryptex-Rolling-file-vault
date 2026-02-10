import os
import tempfile
import pathlib
import hashlib
import json
import shutil
import os
import pytest

from core.key_manager import KeyManager
import core.crypto_engine as crypto_engine
import vault.file_manager as vf

STREAM_TEST_BYTES = int(os.environ.get('STREAM_TEST_BYTES', str(20 * 1024 * 1024)))  # default 20 MiB; set env to 209715200 for 200 MiB


def _make_pattern_file(path, size):
    pattern = b"0123456789ABCDEF" * 256
    with open(path, 'wb') as f:
        written = 0
        while written < size:
            to_write = min(len(pattern), size - written)
            f.write(pattern[:to_write])
            written += to_write


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def test_encrypt_decrypt_roundtrip():
    tmp = tempfile.mkdtemp()
    try:
        src = os.path.join(tmp, 'large.bin')
        _make_pattern_file(src, STREAM_TEST_BYTES)
        km_meta = os.path.join(tmp, 'km_meta.json')
        km = KeyManager('test-master-secret', km_meta)
        dest_filename = 'large.bin.enc'
        dest_path = os.path.join(tmp, dest_filename)
        # use vault dir under tmp
        vf.VAULT_DIR = tmp
        # store
        meta = vf.store_vault_file_stream(src, dest_filename, km, chunk_size=4 * 1024 * 1024)
        assert meta['state'] == 'completed'
        # decrypt
        out = os.path.join(tmp, 'out.bin')
        vf.retrieve_vault_file_stream(dest_filename, out, km)
        assert os.path.exists(out)
        assert file_sha256(src) == file_sha256(out)
    finally:
        shutil.rmtree(tmp)


def test_interrupt_and_resume():
    tmp = tempfile.mkdtemp()
    try:
        src = os.path.join(tmp, 'large2.bin')
        _make_pattern_file(src, STREAM_TEST_BYTES)
        km_meta = os.path.join(tmp, 'km_meta2.json')
        km = KeyManager('test-master-secret', km_meta)
        dest_filename = 'large2.bin.enc'
        dest_path = os.path.join(tmp, dest_filename)
        vf.VAULT_DIR = tmp
        # simulate interruption after 2 chunks
        meta_partial = crypto_engine.stream_encrypt_file(src, dest_path, km, chunk_size=4 * 1024 * 1024, simulate_stop_after=2)
        assert meta_partial['state'] == 'incomplete'
        # resume
        meta_final = crypto_engine.stream_encrypt_file(src, dest_path, km, chunk_size=4 * 1024 * 1024)
        assert meta_final['state'] == 'completed'
        out = os.path.join(tmp, 'out2.bin')
        vf.retrieve_vault_file_stream(dest_filename, out, km)
        assert file_sha256(src) == file_sha256(out)
    finally:
        shutil.rmtree(tmp)