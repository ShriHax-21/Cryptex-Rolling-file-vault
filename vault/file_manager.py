# vault/file_manager.py
# Handles file listing, deletion, and future vault file operations.
import os

VAULT_DIR = './storage/encrypted'

def list_vault_files():
    if not os.path.exists(VAULT_DIR):
        return []
    return [f for f in os.listdir(VAULT_DIR) if os.path.isfile(os.path.join(VAULT_DIR, f))]

def delete_vault_file(filename):
    path = os.path.join(VAULT_DIR, filename)
    if os.path.exists(path):
        os.remove(path)
        return True
    return False
