# 🌱 Magical Garden | v2.1.0

<p align="left">
  <img src="https://img.shields.io/badge/System-Deployed-5BCEFA?style=for-the-badge&logo=opsgenie" alt="System Status">
  <img src="https://img.shields.io/badge/Specialization-Python_%7C_PySide6-F5A9B8?style=for-the-badge&logo=python" alt="Specialization">
  <img src="https://img.shields.io/badge/Encryption-PBKDF2_%2B_Fernet-BE7EFF?style=for-the-badge&logo=letsencrypt" alt="Encryption">
  <img src="https://img.shields.io/badge/Recovery-No_Backdoor-white?style=for-the-badge" alt="No Backdoor Policy">
</p>

---

### 🌟 Project Overview

A fully offline, encrypted password manager built to answer one question honestly: what does "the master password is never stored" actually require, end to end, once you stop hand-waving the crypto? Magical Garden derives its encryption key with PBKDF2-HMAC-SHA256 at 600,000 iterations, encrypts every entry with Fernet, and runs entirely on-device — no accounts, no network calls, no telemetry. The interface is built on PySide6: a real dark/light theme system with independent accent colors, a responsive card grid, and animated interactions, all from a single Python file.

---

### 🔓 Access the Vault

**Deployment:** Local-first by design — clone and run, no live/hosted demo applicable.

```bash
pip install PySide6 cryptography
python magical_garden.py
```

---

### 🚀 Technical Features

* **Zero-Knowledge Design:** The master password is never written to disk in any form — only a salted verification token is checked against it on unlock.
* **Deliberate Key Stretching:** PBKDF2-HMAC-SHA256 at 600,000 iterations trades a fraction of a second on unlock for making brute-force attacks against a stolen vault file meaningfully more expensive.
* **No-Backdoor Recovery Model:** If the key-verification file is ever lost, the app does not quietly let you "reset" your way back in — a new password can never decrypt the old vault, so it refuses to pretend otherwise. Recovering from that state requires a typed confirmation before anything is erased.
* **Live Password Intelligence:** Built-in generator with a real-time entropy/strength estimate, plus vault-wide detection of reused passwords across entries.
* **Tag & Search System:** Every entry is taggable and searchable, with tags manageable independently of the entries themselves.
* **Independent Theme Engine:** Dark/Light mode and accent color are separate, persisted choices — not a fixed palette per mode.
* **Portable Backups:** CSV export/import for moving a vault between machines without touching the underlying encryption.
* **Single-File Architecture:** The entire application — UI, crypto engine, and data layer — ships as one editable Python file.

---

### 🛠️ The Stack

* **Python:** Core application logic, crypto engine, and data handling.
* **PySide6 (Qt):** Custom-built interface — theming, layout, and animation, with nothing left to default widget styling.
* **cryptography (PBKDF2 + Fernet):** Key derivation and authenticated encryption (AES-128-CBC + HMAC-SHA256) for the vault.
* **JSON:** Internal structure for vault entries before encryption and for local (non-secret) preferences — never written to disk unencrypted.

---

### 📂 Repository Structure

```text
├── magical_garden.py     # The entire application — UI, crypto engine, and data layer
├── vault/                 # Auto-created on first run — garden.enc + sunlight.key (back these up together)
└── config/                 # Auto-created on first run — preferences & generator settings (no secrets)
```

---

### ✏️ Customizing This Build

Every piece of user-facing text — app name, version, screen copy, even core vocabulary like "Vault" or "Entry" — lives in one clearly marked `EDITABLE CONTENT` block near the top of `magical_garden.py`. Renaming or reskinning the app never means hunting through rendering logic to find where a label is hard-coded.

---

### Copyright (c) 2026 Vinayak Burgess. All Rights Reserved.
