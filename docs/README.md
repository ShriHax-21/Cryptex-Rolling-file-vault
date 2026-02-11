# 🔐 Cryptex – Rolling File Vault

**Secure Cryptographic File Storage with Key Rotation & Integrity Guarantees**

---

## 📌 Overview

Cryptex – Rolling File Vault is a cryptography-focused secure storage system designed to demonstrate correct implementation of modern security principles.

The system provides:

* Strong AES-256 file encryption
* Cryptographic integrity verification
* Structured key derivation and rotation
* Optional database-backed metadata storage
* Clear threat modeling and architectural separation

This project prioritizes **cryptographic correctness over convenience**. Each component is designed with security-first logic rather than demonstration-only encryption.

Cryptex is suitable for:

* Bachelor-level cybersecurity coursework
* Cryptography demonstrations
* Secure systems design evaluation
* Portfolio-level security engineering

---

## 🎯 Design Objectives

Cryptex was built around the following goals:

* Implement secure AES-based file encryption
* Enforce structured key derivation
* Support controlled key rotation
* Provide tamper detection via cryptographic integrity
* Maintain separation between encryption, storage, and UI layers
* Include documented threat modeling

---

## 🧠 Threat Model

Cryptex assumes:

* An attacker may gain access to encrypted storage
* An attacker may attempt file tampering
* An attacker may attempt metadata modification
* The master password remains secret

| Threat                     | Mitigation                        |
| -------------------------- | --------------------------------- |
| Unauthorized file access   | AES-256 encryption                |
| File tampering             | SHA-256 / HMAC verification       |
| Key compromise             | Controlled key rotation mechanism |
| Replay / overwrite attacks | Metadata validation checks        |
| Accidental corruption      | Structured decryption workflow    |

---

## 🔑 Cryptographic Architecture

### Encryption

* **Algorithm:** AES (Advanced Encryption Standard)
* **Mode:** CBC or GCM (GCM recommended)
* **Key Size:** 256-bit
* **Padding:** PKCS7 (when applicable)

Each file is encrypted independently using a derived file-level key.

---

### Integrity

Cryptex supports:

* SHA-256 hashing for tamper detection
* Optional HMAC-SHA256 for authenticated integrity

| Feature           | Integrity | Authentication |
| ----------------- | --------- | -------------- |
| Detects tampering | Yes       | Yes            |
| Proves origin     | No        | Yes            |
| Uses secret key   | No        | Yes            |

Integrity verification is enforced by default. Authentication can be enabled for advanced use cases.

---

### Key Management

The vault implements structured key handling:

* Master key derived from user secret
* File-level encryption keys
* Controlled rotation lifecycle
* Backward compatibility for previously encrypted files

Cryptex avoids:

* Hardcoded keys
* IV reuse
* Misuse of hashing as encryption

---

## 🔁 Key Rotation Model

Cryptex supports rolling key management:

1. A new encryption key is generated
2. Future files use the new key
3. Previous keys remain available for decryption
4. Key reuse across cycles is prevented

This simulates enterprise-grade key lifecycle handling without forcing full re-encryption of all files simultaneously.

---

## 🗄️ Storage Architecture

Cryptex supports two storage modes:

### Filesystem Mode

* Encrypted files stored in `storage/encrypted/`
* Metadata stored in `storage/metadata.json`

### SQLite Mode (Optional)

* Centralized metadata and file blobs in `vault.db`
* Implemented via `core/db.py`
* Path configurable via `SQLITE_DB_PATH` environment variable

The database may store:

* Password metadata
* Encryption keys
* File metadata
* Vault configuration entries

Security considerations:

* Restrict file permissions for `vault.db`
* Avoid storing raw derived keys directly (store KDF parameters instead)

---

## 🖥️ User Interface

* Language: Python 3.x
* GUI Toolkit: Tkinter
* Password-gated startup
* Integrated vault explorer
* Encrypt / Decrypt workflow
* Structured status and error reporting

The interface is intentionally minimal while preserving backend cryptographic separation.

---

## 📂 Project Structure

Cryptex-Rolling-File-Vault/

core/
		crypto_engine.py
		key_manager.py
		integrity.py
		db.py
		vault_session.py

gui/
		app.py

vault/
		explorer.py
		file_manager.py
		ui.py

docs/
		architecture.md
		threat_model.md
		VAULT_ROADMAP.md
		ALGORITHMS.md

requirements.txt
main.py
LICENSE

---

## ⚙️ Requirements

### Software

* Python 3.10+
* Tkinter
* PyCryptodome
* hashlib (standard library)

### Operating Systems

* Linux (primary development environment)
* Windows
* macOS

---

## 🚀 Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

---

## 📦 Building Executable (Optional)

```bash
pyinstaller --onefile --windowed --name CryptexVault main.py
```

The executable will be generated inside:

dist/

---

## 📚 Engineering Principles

Cryptex demonstrates:

* Proper separation of cryptographic responsibilities
* Realistic key lifecycle handling
* Explicit threat modeling
* Storage abstraction
* Practical application of cryptographic theory

Many student cryptography projects fail because they:

* Skip integrity verification
* Hardcode secrets
* Reuse IVs
* Confuse hashing with encryption
* Ignore threat modeling

Cryptex is designed to avoid those architectural failures.

---

If you want, I can now:

* Make this more academically formal
* Make it more portfolio-aggressive
* Or audit your crypto claims line by line and tell you what’s actually solid vs marketing

Your move.
