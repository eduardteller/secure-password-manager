# Security Report: Secure Password Manager

## Overview

This report details the encryption methods, memory management practices, and security features implemented in the Secure Password Manager (SPM).

---

## 1. Encryption Methods

### Password Encryption: AES-256-GCM

All stored passwords use **AES-256-GCM** (Galois/Counter Mode).

| Component | Value               |
| --------- | ------------------- |
| Algorithm | AES-256-GCM         |
| Key Size  | 256 bits (32 bytes) |
| IV Size   | 96 bits (12 bytes)  |
| Auth Tag  | 128 bits (16 bytes) |

**Why this matters:**

- AES-256 is military-grade encryption
- GCM mode detects if someone tampers with the data
- Each encryption uses a fresh random IV, so the same password produces different ciphertext

### Key Derivation: PBKDF2

The master password is converted into an encryption key using **PBKDF2**.

| Setting    | Value               |
| ---------- | ------------------- |
| Algorithm  | PBKDF2-HMAC         |
| Iterations | 100,000             |
| Salt Size  | 128 bits (16 bytes) |
| Output Key | 256 bits (32 bytes) |

**Why this matters:**

- Makes brute-force attacks extremely slow
- Random salt prevents rainbow table attacks
- 100,000 iterations takes time for attackers but is acceptable for users

### Master Password Storage

The master password is **never stored in plain text**. Instead:

1. A random salt is generated
2. PBKDF2 creates a hash from password + salt
3. Only the salted hash is saved
4. Verification uses timing-safe comparison (`CRYPTO_memcmp`)

### Random Number Generation

All random values (salts, IVs, session IDs) use OpenSSL's `RAND_bytes`, which is a cryptographically secure random number generator.

---

## 2. Memory Management

### Secure Wiping

Sensitive data is wiped from memory immediately after use using `OPENSSL_cleanse`.

**Data that gets wiped:**
| Data | When Wiped |
|------|------------|
| Derived encryption keys | After each encrypt/decrypt operation |
| Decrypted passwords | After conversion to output |
| Master password | When vault is locked |
| All entries | When vault object is destroyed |

### Implementation Details

```
secureWipe(string& data)    → Overwrites with zeros, then clears
secureWipe(vector& data)    → Overwrites with zeros, then clears
```

**Why `OPENSSL_cleanse` instead of regular overwrite:**

- Regular memory clearing can be optimized away by compilers
- `OPENSSL_cleanse` is guaranteed to actually overwrite the memory

### Vault Cleanup

When the vault is closed or the program exits:

1. Master password hash is wiped
2. Current master password is wiped
3. All encrypted entries are wiped
4. Entry map is cleared

### Prevention Measures

| Threat           | Protection                        |
| ---------------- | --------------------------------- |
| Memory leaks     | Automatic cleanup in destructors  |
| Buffer overflows | Size validation on all inputs     |
| Leftover data    | Immediate secure wiping after use |

---

## 3. Security Features

### Input Validation

All user inputs are validated before use:

| Input Type      | Rules                                                 |
| --------------- | ----------------------------------------------------- |
| Service name    | Alphanumeric + dashes/dots/underscores, max 256 chars |
| Username        | Valid email or alphanumeric, max 256 chars            |
| Password        | 1-1024 characters, no null bytes                      |
| Master password | 8+ chars, must have uppercase, lowercase, and digit   |
| File paths      | No directory traversal (../), no system paths         |

### Input Sanitization

Dangerous characters are stripped from all inputs:

- Shell command characters: `; | & $ \` < >`
- Control characters (except newline and tab)

This prevents injection attacks.

### File Security

| Protection           | How                                      |
| -------------------- | ---------------------------------------- |
| File permissions     | Set to 600 (owner read/write only)       |
| Path validation      | Blocks access to /etc, /sys, /proc, /dev |
| Traversal prevention | Rejects paths with `..` or `//`          |

### UI Security

| Feature           | Implementation                                    |
| ----------------- | ------------------------------------------------- |
| Password input    | Echo disabled (characters not shown)              |
| Password display  | Never shown on screen                             |
| Clipboard         | Password copied to clipboard instead of displayed |
| Clipboard timeout | Auto-cleared after 30 seconds                     |
| Confirmation      | Destructive actions require "yes" confirmation    |

### Error Handling

| For Users             | For Logs                          |
| --------------------- | --------------------------------- |
| Generic messages only | Detailed event information        |
| No stack traces       | Structured format with timestamps |
| No internal details   | Session IDs for tracking          |

**Example:**

- User sees: "Authentication failed"
- Log records: `[SECURITY] [UNLOCK_FAILURE] [Session: xyz123] Authentication failed`

### Audit Logging

Every operation is logged with:

- Timestamp (with milliseconds)
- Log level (INFO, WARNING, ERROR, SECURITY)
- Event type (UNLOCK, ADD_ENTRY, DELETE_ENTRY, etc.)
- Session ID
- IP address
- Outcome (success/failure)

**What is NOT logged:**

- Passwords (master or entry)
- Decrypted content
- Encryption keys
- Tokens or secrets

Log files are also set to 600 permissions (owner-only access).

### Session Management

- Each vault instance gets a unique random session ID
- Session IDs are logged with all operations
- Helps trace activity back to specific sessions

### Access Control

- Vault file permissions restrict access to owner only
- Log file permissions restrict access to owner only
- Master password required for all operations
- Vault auto-locks after each command completes

---

## 4. Dependencies

| Library | Purpose                      |
| ------- | ---------------------------- |
| OpenSSL | All cryptographic operations |

OpenSSL is a widely-used, well-audited cryptographic library.
