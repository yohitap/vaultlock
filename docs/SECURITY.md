# Security design notes

## Implemented

1. Credential values are encrypted before being written to SQLite.
2. Fernet provides authenticated symmetric encryption.
3. PBKDF2-HMAC-SHA256 derives a key from the master password.
4. The application does not store the master password.
5. Login sessions expire after 30 minutes.
6. Password generation uses Python's `secrets` module.
7. Password health detects weak, reused and old passwords.
8. Audit events record login/logout and vault changes.

## Important limitation

This portfolio implementation keeps a derived key in process memory after login. That is acceptable for a local educational project but is not a complete production-grade architecture.

A production password manager should consider:

- client-side encryption
- secure key wrapping
- server-side session storage
- CSRF protection
- rate limiting
- MFA
- secure HTTP headers
- HTTPS
- backup/recovery design
- memory/key lifecycle handling
- independent security review
