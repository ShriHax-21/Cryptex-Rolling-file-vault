# Cryptex Rolling File Vault: Roadmap to Full Vault Functionality

## 1. Vault File Management UI
- Add a file browser/list in the GUI to show all files in the vault (`storage/encrypted`).
- Allow users to:
  - View the list of encrypted files.
  - Select a file to decrypt or delete.
  - Add (import) new files to the vault (encrypt and store).

## Progress Update (20 January 2026)

**Status:** ~75% complete

- **Implemented:**
  - `VaultExplorer` file list added and integrated into the main GUI.
  - Clicking/selecting a file in the vault updates the Browse path (wired `on_select` → `VaultApp._on_vault_select`).
  - Encrypt/decrypt functions implemented and file header format (JSON header + ciphertext) supported for AES/DES/3DES modes.
  - Fixed `decrypt_file()` syntax and defined missing variables (`ciphertext`, `enc_dict`) so decryption runs correctly.
  - Key management: basic `KeyManager` added; app shows a password prompt at startup to derive/rotate keys and initializes `CryptoEngine`.
  - UI polish: switched app fonts to JetBrains Mono, resized widgets to avoid overlaps, centered and fixed window size (840x690), increased output box height, and autofocus + Enter binding for the password field.
  - Added graceful error messages to output box and improved layout packing so widgets don't overlap.

- **Partially done / Needs user setup:**
  - JetBrains Mono / Fira Code fonts should be installed on the host to avoid Qt font warnings (system step).

- **Remaining / Next steps:**
  1. Add file import (encrypt & add) flow in GUI (Import button + drag/drop support).
  2. Add delete-with-confirmation for vault files.
  3. Improve key storage UX (change password, persistent master-secret handling, secure KDF iteration tuning).
  4. Add integrity/hmac checks and show verification results when decrypting.
  5. Add double-click actions (open/decrypt) and export dialog to choose destination for decrypted files.
  6. Add graceful fallback when JetBrains Mono is unavailable (font fallback).

If you want, I can implement any of the next steps now — tell me which one to prioritise.

## 2. Add/Import File to Vault
- Add a button to import a file.
- Encrypt imported files and store them in `storage/encrypted`.
- Update the file list in the UI after import.

## 3. Remove/Delete File from Vault
- Allow users to select and delete encrypted files from the vault.
- Confirm deletion before removing files.

## 4. Decrypt and Export File
- Allow users to select an encrypted file and decrypt it.
- Let users choose where to save the decrypted file (export).

## 5. File Metadata and Integrity
- Store metadata (original filename, date added, etc.) for each file (e.g., in `metadata.json`).
- Optionally, store and check file hashes for integrity verification.

## 6. Access Control and Security
- Ensure the vault is only accessible after password entry.
- Optionally, add features like password change, lock after inactivity, etc.

## 7. Polish the UI
- Make the file list user-friendly (show file names, sizes, dates).
- Add status messages, error handling, and confirmations for actions.

## 8. Testing and Packaging
- Test on a clean system to ensure all dependencies are listed in `requirements.txt`.
- Optionally, create a script or installer for easy setup.

---

### Optional Advanced Features
- Search/filter files in the vault.
- File previews (for text/images).
- Audit log of actions.
- Multi-user support.

---

**Start with Step 1: Add a file browser/list to your GUI for vault file management.**
