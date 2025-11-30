# Secure Password Manager - Test Cases

Manual test guide to verify the password manager works correctly and securely.

---

## Prerequisites

1. Build the application:
   ```bash
   cd build && make
   ```
2. Remove any existing vault before testing:
   ```bash
   rm -f ~/.spm_vault ~/.spm_log
   ```

---

## 1. Basic Commands

### 1.1 Help Command

**Steps:**

1. Run `./spm help`

**Expected:** Shows list of commands (init, add, get, update, list, delete) and security features.

### 1.2 Version Command

**Steps:**

1. Run `./spm version`

**Expected:** Shows "Secure Password Manager v1.0.0"

### 1.3 No Arguments

**Steps:**

1. Run `./spm`

**Expected:** Shows help message.

### 1.4 Unknown Command

**Steps:**

1. Run `./spm unknown`

**Expected:** Shows "Error: Unknown command: unknown" and help message.

---

## 2. Vault Initialization

### 2.1 Create New Vault

**Steps:**

1. Run `./spm init`
2. Enter password: `SecurePass1`
3. Confirm password: `SecurePass1`

**Expected:**

- Shows "Success: Vault initialized successfully"
- File `~/.spm_vault` is created

### 2.2 Password Mismatch

**Steps:**

1. Remove vault: `rm ~/.spm_vault`
2. Run `./spm init`
3. Enter password: `SecurePass1`
4. Confirm password: `DifferentPass1`

**Expected:** Shows "Error: Passwords do not match"

### 2.3 Init When Vault Exists

**Steps:**

1. Ensure vault exists (run 2.1 first)
2. Run `./spm init`

**Expected:** Shows "Error: Vault already exists at this location"

---

## 3. Password Management

### 3.1 Add Entry

**Steps:**

1. Run `./spm add`
2. Enter master password: `SecurePass1`
3. Enter service: `github.com`
4. Enter username: `user@email.com`
5. Enter password: `MyGitHubPass123`

**Expected:** Shows "Success: Password added for github.com"

### 3.2 List Services

**Steps:**

1. Run `./spm list`
2. Enter master password: `SecurePass1`

**Expected:** Shows "Stored services (1):" followed by "- github.com"

### 3.3 Get Credentials

**Steps:**

1. Run `./spm get`
2. Enter master password: `SecurePass1`
3. Enter service: `github.com`

**Expected:**

- Shows service name and username
- Shows "[COPIED TO CLIPBOARD]" (if clipboard available)
- Shows clipboard clear warning (30 seconds)

### 3.4 Update Credentials

**Steps:**

1. Run `./spm update`
2. Enter master password: `SecurePass1`
3. Enter service: `github.com`
4. Leave username empty (press Enter to keep)
5. Enter new password: `NewPassword123`

**Expected:** Shows "Success: Credentials updated for github.com"

### 3.5 Delete Entry

**Steps:**

1. Run `./spm delete`
2. Enter master password: `SecurePass1`
3. Enter service: `github.com`
4. Confirm: `yes`

**Expected:** Shows "Success: Entry deleted"

### 3.6 Cancel Delete

**Steps:**

1. Add an entry first
2. Run `./spm delete`
3. Enter master password
4. Enter service name
5. Confirm: `no`

**Expected:** Shows "Deletion cancelled"

---

## 4. Authentication Tests

### 4.1 Wrong Master Password

**Steps:**

1. Run `./spm list`
2. Enter wrong password: `WrongPass1`

**Expected:** Shows "Error: Authentication failed"

### 4.2 Empty Master Password

**Steps:**

1. Run `./spm list`
2. Press Enter (empty password)

**Expected:** Shows "Error: Authentication failed"

### 4.3 No Vault Exists

**Steps:**

1. Remove vault: `rm ~/.spm_vault`
2. Run `./spm add`

**Expected:** Shows "Error: Vault does not exist. Use 'spm init' first"

---

## 5. Input Validation

### 5.1 Master Password Requirements

#### 5.1.1 Too Short (less than 8 chars)

**Steps:**

1. Remove vault: `rm ~/.spm_vault`
2. Run `./spm init`
3. Enter password: `Short1`

**Expected:** Shows validation error about password requirements.

#### 5.1.2 No Uppercase

**Steps:**

1. Run `./spm init`
2. Enter password: `lowercase123`

**Expected:** Shows validation error about missing uppercase.

#### 5.1.3 No Lowercase

**Steps:**

1. Run `./spm init`
2. Enter password: `UPPERCASE123`

**Expected:** Shows validation error about missing lowercase.

#### 5.1.4 No Digit

**Steps:**

1. Run `./spm init`
2. Enter password: `NoDigitsHere`

**Expected:** Shows validation error about missing digit.

### 5.2 Service Name Validation

#### 5.2.1 Empty Service Name

**Steps:**

1. Run `./spm add`
2. Enter correct master password
3. Press Enter for service (empty)

**Expected:** Shows validation error about invalid service name.

#### 5.2.2 Special Characters in Service

**Steps:**

1. Run `./spm add`
2. Enter correct master password
3. Enter service: `test@#$%`

**Expected:** Shows validation error (only alphanumeric, dash, dot, underscore allowed).

#### 5.2.3 Valid Service Names

**Steps:**

1. Test these service names: `github.com`, `my-service`, `test_site`

**Expected:** All should be accepted.

### 5.3 Username Validation

#### 5.3.1 Empty Username

**Steps:**

1. Run `./spm add`
2. Enter correct master password
3. Enter valid service
4. Press Enter for username (empty)

**Expected:** Shows validation error about invalid username.

#### 5.3.2 Valid Email Format

**Steps:**

1. Enter username: `user@example.com`

**Expected:** Should be accepted.

#### 5.3.3 Valid Alphanumeric Username

**Steps:**

1. Enter username: `john_doe123`

**Expected:** Should be accepted.

---

## 6. Security Tests

### 6.1 Vault File Permissions

**Steps:**

1. Create vault with `./spm init`
2. Run: `ls -la ~/.spm_vault`

**Expected:** Permissions should be `-rw-------` (600 - owner read/write only).

### 6.2 Encrypted Storage

**Steps:**

1. Create vault and add entries
2. Run: `cat ~/.spm_vault`

**Expected:** Shows binary/encrypted data, no readable passwords or usernames.

### 6.3 Password Not Echoed

**Steps:**

1. Run `./spm init`
2. Type password

**Expected:** Characters are not shown on screen while typing.

### 6.4 Clipboard Auto-Clear

**Steps:**

1. Run `./spm get` for an entry
2. Wait 30 seconds
3. Try to paste from clipboard

**Expected:** Clipboard should be empty after 30 seconds.

### 6.5 Audit Logging

**Steps:**

1. Perform various operations
2. Run: `cat ~/.spm_log`

**Expected:** Log file shows:

- Timestamps for all operations
- Success/failure status
- Event types (INIT, ADD_ENTRY, GET_ENTRY, etc.)
- No actual passwords in logs

### 6.6 Failed Auth Logging

**Steps:**

1. Try to unlock with wrong password 3 times
2. Check log: `cat ~/.spm_log`

**Expected:** Each failed attempt is logged with UNLOCK_FAILURE.

---

## 7. Edge Cases

### 7.1 Service Not Found

**Steps:**

1. Run `./spm get`
2. Enter correct master password
3. Enter service: `nonexistent`

**Expected:** Shows "Error: Entry not found for service 'nonexistent'"

### 7.2 Update Non-Existent Service

**Steps:**

1. Run `./spm update`
2. Enter correct master password
3. Enter service: `nonexistent`

**Expected:** Shows "Error: Entry not found for service 'nonexistent'"

### 7.3 Delete Non-Existent Service

**Steps:**

1. Run `./spm delete`
2. Enter correct master password
3. Enter service: `nonexistent`

**Expected:** Shows "Error: Entry not found for service 'nonexistent'"

### 7.4 Empty Vault List

**Steps:**

1. Create new vault (no entries)
2. Run `./spm list`
3. Enter master password

**Expected:** Shows "No entries in vault"

### 7.5 Overwrite Existing Entry

**Steps:**

1. Add entry for `github.com`
2. Add another entry for `github.com` with different credentials

**Expected:** Old entry is replaced with new one.

### 7.6 Long Password

**Steps:**

1. Run `./spm add`
2. Enter a password with 500 characters

**Expected:** Should be accepted (max is 1024 chars).

### 7.7 Special Characters in Password

**Steps:**

1. Add entry with password: `P@$$w0rd!#%^&*()[]{}|;:'",.<>?`

**Expected:** Password should be stored and retrieved correctly.

---

## 8. Input Sanitization

### 8.1 Shell Injection Prevention

**Steps:**

1. Run `./spm add`
2. Try service name: `test; rm -rf /`

**Expected:**

- Semicolon is stripped from input
- No shell command is executed
- Shows validation error (invalid characters)

### 8.2 Command Substitution Prevention

**Steps:**

1. Try input: `$(whoami)`

**Expected:** Dollar sign and backticks are stripped.

### 8.3 Pipe Prevention

**Steps:**

1. Try input: `test | cat /etc/passwd`

**Expected:** Pipe character is stripped.

---

## 9. Multiple Entries

### 9.1 Add Multiple Services

**Steps:**

1. Add entries for: `github.com`, `gitlab.com`, `bitbucket.org`
2. Run `./spm list`

**Expected:** All three services are shown.

### 9.2 Retrieve Specific Entry

**Steps:**

1. With multiple entries, get `gitlab.com`

**Expected:** Shows only gitlab.com credentials.

### 9.3 Delete One of Many

**Steps:**

1. Delete `github.com`
2. Run `./spm list`

**Expected:** github.com is gone, others remain.
