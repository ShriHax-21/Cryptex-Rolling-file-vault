# Cryptex — Vault Architecture

This document describes the high-level architecture, main components, data flows, file formats, and security recommendations for the Cryptex Rolling File Vault project.

## Overview

Cryptex is a local file vault application that protects files using symmetric encryption. Major responsibilities are split across a small `core` library (cryptography and key management), a `vault` layer (file discovery and management), a `gui` (user interaction), and `storage` (on-disk metadata and encrypted blobs).

## Components

- Core: cryptographic primitives and session management.
  - Key files: `core/key_manager.py` — derives keys from the master secret and manages key rotation.
  - Crypto engine: `core/crypto_engine.py` — encrypts/decrypts data (AES modes supported).
  - Vault session: `core/vault_session.py` — manages an unlocked session, verifies vault identity via an encrypted `vault_id` blob, and exposes `crypto_engine`.
  - Integrity helpers: `core/integrity.py` — HMAC utilities.

- Vault layer: file and UI-backed file operations.
  - Explorer / file manager: `vault/explorer.py`, `vault/file_manager.py` — show vault contents, encrypt/decrypt files on demand.

- GUI: `gui/app.py` — password prompt, unlock flow, and main UI wiring. The GUI collects a master password, creates a `VaultSession`, and then uses `VaultExplorer` to present files.

- Storage: `storage/metadata.json` — stores key metadata (salts/keys in current implementation) and `storage/encrypted/` / `storage/decrypted/` for file blobs.

- Database (optional): `core/db.py` provides an SQLite-backed alternative to file-based storage. It defines tables for `password_meta`, `keys`, `files`, and generic `meta` values and is used when `DB` can be imported and initialized. The DB file defaults to `vault.db` and can be changed with the `SQLITE_DB_PATH` environment variable.

  - When present, `KeyManager` will read/write password and keys to the DB, `VaultSession` will store the `vault_id` verifier in the DB `meta` table, and `vault/file_manager.py` will store encrypted file blobs in the DB `files` table instead of the filesystem.

  - Important: the DB centralizes metadata and file blobs but still requires strong filesystem permissions to protect sensitive content. See `core/db.py` for schema and helper functions.

## Key derivation & algorithms (current implementation)

- Key Derivation: PBKDF2-HMAC-SHA256 with a per-key salt and an iteration count.
  - Implementation: `core/key_manager.py` uses `hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=32)` with `DEFAULT_ITERATIONS = 200_000`.
  - Derivation call (conceptual): `pbkdf2_hmac('sha256', master_secret.encode(), salt, iterations, dklen=32)`
- Symmetric cipher: AES with GCM or other modes in `CryptoEngine` / `core/crypto_engine.py`.
- Vault identity: `VAULT_ID_PATH` contains a JSON blob with `nonce`, `ciphertext`, `tag` (AES-GCM) used to verify a candidate key can decrypt the vault identity.

## Unlock / Initialization flows

- Unlock (existing vault):
  1. GUI gets password and passes it to `VaultSession(master_secret, metadata_path)`.
  2. `VaultSession.unlock()` calls `KeyManager.get_latest_key()` to obtain the latest stored key and salt.
  3. `VaultSession` constructs `CryptoEngine` and attempts to decrypt the `vault_id` blob using the derived key.
  4. If decryption succeeds, `unlocked = True` and the session proceeds; otherwise an exception is raised.

- Initialization (current behavior / insecure):
  - If `KeyManager.get_latest_key()` returns `None`, `rotate_key()` is called which creates a new salt and derives a new key from the provided password and then saves the derived key (hex) into `metadata.json`. The vault id is created and encrypted with this new key.
  - Effect: any password will create a working key when metadata/vault-id are missing, which allows arbitrary text to "unlock" a vault that hasn't been properly initialized.

## File formats

- `storage/metadata.json` (current): stores a mapping of salt hex -> derived key hex (this is insecure; derived keys should not be stored in plaintext on disk).
- `VAULT_ID_PATH`: AES-GCM JSON blob with `nonce`, `ciphertext`, `tag`.

## Security issues observed

- Weak KDF: using a single SHA-256 digest of (password || salt) is insufficient against brute-force attacks. No work factor (iterations/memory) is used.
- Derived keys stored on disk: `metadata.json` currently saves derived key hex values — this leaks the key material and defeats password protection.
- Insecure initialization flow: `rotate_key()` is invoked automatically if no key exists, allowing any password to initialize the vault stealthily. There is no explicit "create vault" action.
- Lack of KDF parameters and metadata: salts and KDF algorithm/parameters are not recorded in a standard way.

## Recommended fixes and hardening

- Use a modern password-based KDF instead of plain SHA-256. Options:
  - PBKDF2-HMAC-SHA256 with a high iteration count (e.g., >= 200k), or
  - Argon2id with recommended memory/time/parallelism parameters.

- Do NOT store derived keys in `metadata.json`.
  - Instead store only the KDF parameters (salt, algorithm, iterations/memory) and an authentication verifier (encrypted vault ID or HMAC) that can be used to verify password correctness.
  - Example: store `metadata.json` with `{ "kdf": "pbkdf2", "salt": "...", "iter": 200000 }` and store the vault identity encrypted with the derived key; never store the key itself.

- Initialization vs Unlock:
  - Make vault *creation* an explicit operation (UI: "Create new vault"), which writes metadata and vault id.
  - For unlocking an existing vault, only attempt to derive a key from the supplied password using stored KDF params and attempt decryption of `vault_id`; do not rotate/create keys automatically.

- Protect on-disk metadata:
  - Use file permissions (owner-only) for `metadata.json` and `VAULT_ID_PATH`.

- Improve integrity and authentication:
  - Continue to use AES-GCM for authenticated encryption. Consider adding an HMAC layer for any non-AE data.

- Memory hygiene:
  - Zero key material as soon as possible (overwrite sensitive bytearrays) and avoid writing keys to logs or JSON.

## Suggested code changes (high-level)

- `core/key_manager.py`
  - Change `derive_key` to use `hashlib.pbkdf2_hmac('sha256', password, salt, iterations)` or Argon2.
  - Change storage to save only salt and kdf params, not the derived key hex.
  - Modify `get_latest_key()` to return the salt and kdf params only; derivation should occur in-memory during unlock.

- `core/vault_session.py`
  - Do not call `rotate_key()` automatically when a key is missing. Instead, if no metadata/vault-id exists, indicate "vault not initialized" and require an explicit initialization flow.
  - Use the derived key (from KDF) to decrypt `vault_id` and fail on any authentication error.

## Operational notes

- Backward compatibility: migrating existing `metadata.json` that currently stores derived keys will require a one-time migration utility which:
  1. Prompts for the old master password,
  2. Derives the key using the old method to decrypt `vault_id`,
  3. Re-encrypts `vault_id` with a new key derived via the new KDF and writes updated `metadata.json` with KDF params (without storing the key).

- UX: Add explicit "Create vault" and "Unlock existing vault" flows in `gui/app.py`. Make error messages for wrong password generic to avoid leaking information.

## Summary

The application currently provides a sensible separation of responsibilities, but several security-critical areas need improvement: adopt a strong KDF (PBKDF2/Argon2), stop storing derived keys on disk, and make vault initialization explicit. Implementing these changes will harden the vault against trivial unlocking and brute-force attacks.

---
Created for the Cryptex Rolling File Vault codebase.
