
# 🔐 Cryptex – Rolling File Vault

**Secure Cryptographic File Storage with Key Rotation & Integrity Guarantees**

---

## 📌 Project Overview

**Cryptex – Rolling File Vault** is a cybersecurity-focused project that implements a **secure file storage system** using **strong cryptographic primitives**, **automatic key rotation**, and **cryptographic integrity verification**.

The system is designed to:

* Protect files **at rest**
* Prevent **unauthorized access**
* Detect **tampering or corruption**
* Demonstrate **correct cryptographic design**, not just encryption-for-show

This project is intentionally built with **academic clarity** and **industry-relevant security principles**, making it suitable for:

* Bachelor-level cybersecurity coursework
* Cryptography demonstrations
* Secure systems design evaluation

---

## 🎯 Core Objectives

* Implement **AES-based file encryption**
* Enforce **secure key management and rotation**
* Ensure **cryptographic integrity verification**
* Compare **Integrity vs Authentication**
* Provide a **simple GUI-based user interface**
* Maintain **clear documentation and threat awareness**

---

## 🧠 Threat Model (High-Level)

| Threat                     | Mitigation                            |
| -------------------------- | ------------------------------------- |
| Unauthorized file access   | AES encryption                        |
| File tampering             | Cryptographic hashes (HMAC / SHA-256) |
| Key compromise             | Rolling key rotation                  |
| Replay / overwrite attacks | Metadata validation                   |
| Accidental data loss       | Controlled decryption workflow        |

---

## 🔑 Cryptographic Design

### 🔹 Encryption

* **Algorithm:** AES (Advanced Encryption Standard)
* **Mode:** CBC or GCM (recommended)
* **Key Size:** 256-bit
* **Padding:** PKCS7 (if applicable)

### 🔹 Integrity

* SHA-256 hash
* Optional HMAC for keyed integrity

### 🔹 Key Management

* Master key derived from user secret
* File-level encryption keys
* **Automatic key rotation** without re-encrypting all files at once

> ⚠️ Brutal truth: If you hardcode keys, reuse IVs, or skip integrity checks — your system is **cryptographically broken**, not “simplified”.

---

## 🔁 Secure Key Rotation

The vault periodically:

1. Generates a **new encryption key**
2. Encrypts future files with the new key
3. Maintains old keys securely for backward decryption
4. Prevents key reuse across rotation cycles

This simulates **real-world enterprise key lifecycle management**.

---

## 🧪 Integrity vs Authentication (Comparison)

| Feature            | Integrity | Authentication |
| ------------------ | --------- | -------------- |
| Detects tampering  | ✅         | ✅              |
| Proves file origin | ❌         | ✅              |
| Uses secret key    | ❌         | ✅              |
| Example            | SHA-256   | HMAC-SHA256    |

This project **implements integrity by default** and optionally supports authentication for advanced users.

---

## 🖥️ User Interface

* **Language:** Python (Python 5 reference / Python 3.x compatible)
* **GUI Toolkit:** Tkinter
* Simple file selection
* Encrypt / Decrypt buttons
* Status feedback and error handling

No CLI-only nonsense. This is usable by non-technical users.

---

## 📂 Project Architecture

```
Cryptex-Rolling-File-Vault/
│
├── core/
│   ├── crypto_engine.py
│   ├── key_manager.py
│   ├── integrity.py
│
├── gui/
│   ├── app.py
│
├── storage/
│   ├── encrypted/
│   ├── decrypted/
│   ├── metadata.json
│
├── docs/
│   ├── threat_model.md
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

## ⚙️ Requirements

### 🔧 Software

* Python **3.10+**
* Tkinter
* PyCryptodome
* hashlib (standard library)
* ClickUp (for project timeline tracking)

### 🖥️ Operating System

* Linux (preferred)
* Windows (supported)
* macOS (supported)

---

---

## 🧠 Why This Project Matters

This is **not** a toy encryption demo.

It demonstrates:

* Correct cryptographic separation of concerns
* Realistic key lifecycle handling
* Security tradeoffs explained, not hidden
* Practical application of cryptography theory

Most student crypto projects fail because they:

* Ignore integrity
* Hardcode secrets
* Confuse hashing with encryption
* Have zero threat model

This one doesn’t — **if you implement it properly**.






<!-- use pyqt5 or 6 -->