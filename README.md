# VaultLock

VaultLock is a security-focused password manager built with Python, Flask, SQLite and the `cryptography` library.

## Why this project is different

Instead of being only a CRUD password manager, VaultLock focuses on practical password-security problems:

- Encrypted credential fields at rest
- Strong master-password policy
- Secure random password generation
- Password health score
- Detection of weak credentials
- Detection of password reuse across saved accounts
- Detection of credentials not changed for 180+ days
- Auto-expiring login session
- Security audit log
- Categories and notes for real-world organization
- No plaintext credential fields are stored in SQLite

## Stack

- Python
- Flask
- SQLite
- Cryptography / Fernet
- PBKDF2-HMAC-SHA256
- HTML/CSS/JavaScript

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open:

http://127.0.0.1:5000

## Security note

This repository is an educational portfolio project, not a production password manager.

The demo keeps a derived vault key in server-side process memory after login. For a production implementation, use a dedicated server-side session/key-management system or move encryption/decryption to the client using Web Crypto/WebAssembly and never send plaintext vault contents to the server.

Also add CSRF protection, rate limiting, secure deployment configuration, HTTPS, a stronger vault-key architecture, secure headers, and a carefully designed backup/recovery mechanism before production use.

## Resume bullet

Built VaultLock, a security-focused password manager using Python, Flask, SQLite and cryptography, with encrypted credential storage, password-health analysis, reuse detection, secure password generation and audit logging.

## Suggested future upgrades

- TOTP authenticator codes
- Encrypted export/import
- Breached-password checking using k-anonymity
- Browser extension
- Client-side Web Crypto encryption
- Biometric unlock where supported
- Password expiration reminders
- Multi-device synchronization
- Rate limiting and account lockout
- CSP/security headers
