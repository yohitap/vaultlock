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

Built VaultLock, a security-focused password manager using Python, Flask, SQLite and cryptography, with encrypted credential storage, password-health analysis, reuse detection, secure password generation and audit logging.

