"""Migrate existing storage/metadata.json and storage/encrypted into the local SQLite DB (vault.db).

By default this creates `vault.db` in the project root. You can set `SQLITE_DB_PATH`
to a different path before running this script.
"""
import json
import os
import glob
from core.db import DB


def migrate(metadata_path='storage/metadata.json'):
    if not os.path.exists(metadata_path):
        print('No metadata file found at', metadata_path)
        return
    with open(metadata_path, 'r') as f:
        data = json.load(f)

    db = DB()
    db.init_db()

    pwd = data.get('password')
    if pwd:
        try:
            db.set_password_meta(pwd.get('salt'), pwd.get('hash'), int(pwd.get('iterations', DB.DEFAULT_ITERATIONS) if hasattr(DB,'DEFAULT_ITERATIONS') else int(pwd.get('iterations', 200000))))
            print('Migrated password metadata')
        except Exception as e:
            print('Failed to migrate password metadata:', e)

    keys = data.get('keys', {})
    for salt, key_hex in keys.items():
        try:
            db.store_key(salt, key_hex)
        except Exception as e:
            print('Failed to store key', salt, e)

    # Migrate encrypted files from storage/encrypted
    enc_dir = os.path.join('storage', 'encrypted')
    if os.path.isdir(enc_dir):
        for path in glob.glob(os.path.join(enc_dir, '*')):
            try:
                name = os.path.basename(path)
                with open(path, 'rb') as f:
                    content = f.read()
                # try to parse header (JSON) before the first newline
                parts = content.split(b'\n', 1)
                header = parts[0] if parts else b'{}'
                try:
                    enc_dict = json.loads(header.decode())
                except Exception:
                    enc_dict = {}
                nonce = enc_dict.get('nonce')
                iv = enc_dict.get('iv')
                tag = enc_dict.get('tag')
                alg = enc_dict.get('alg') or None
                mode = enc_dict.get('mode') or None
                db.store_file_blob(name, content, nonce=nonce, iv=iv, tag=tag, alg=alg, mode=mode)
                print('Migrated file', name)
            except Exception as e:
                print('Failed to migrate file', path, e)
    print('Migration completed')


if __name__ == '__main__':
    migrate()
