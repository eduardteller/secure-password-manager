# Secure Password Manager (SPM) - User Manual

A command-line password manager with AES-256 encryption.

## Requirements

- CMake 3.16 or newer
- C++ compiler with C++20 support (GCC 10+, Clang 10+, MSVC 2019+)
- OpenSSL library

## Installing Dependencies

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev xclip
```

### macOS

```bash
brew install cmake openssl
```

### Windows

1. Install [Visual Studio 2019+](https://visualstudio.microsoft.com/) with C++ workload
2. Install [CMake](https://cmake.org/download/)
3. Install OpenSSL:
   - Download from [slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html)
   - Or use vcpkg: `vcpkg install openssl:x64-windows`

## Building

### Linux & macOS

```bash
mkdir build && cd build
cmake ..
make
```

The executable `spm` will be in the `build/` folder.

### Windows (Visual Studio)

```cmd
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Windows (32-bit)

```cmd
cmake .. -G "Visual Studio 17 2022" -A Win32
cmake --build . --config Release
```

## Commands

### Initialize Vault

Create a new password vault. You'll set a master password.

```bash
spm init
```

Master password must have:

- At least 8 characters
- Uppercase and lowercase letters
- At least one digit

### Add Entry

Store a new password.

```bash
spm add
```

You'll be asked for:

1. Master password
2. Service name (e.g., github.com)
3. Username/email
4. Password

### Get Entry

Retrieve stored credentials. Password is copied to clipboard.

```bash
spm get
```

Clipboard clears automatically after 30 seconds.

### List Services

Show all stored service names.

```bash
spm list
```

### Update Entry

Change username or password for an existing entry.

```bash
spm update
```

Press Enter to keep current values.

### Delete Entry

Remove an entry from the vault.

```bash
spm delete
```

Requires confirmation.

### Help & Version

```bash
spm help
spm version
```

## File Locations

| File  | Location       |
| ----- | -------------- |
| Vault | `~/.spm_vault` |
| Logs  | `~/.spm_log`   |

On Windows, these are in `%USERPROFILE%`.

## Security Features

- **AES-256-GCM** encryption for all stored passwords
- **PBKDF2** key derivation from master password
- **Secure memory wiping** after use
- **Input validation** to prevent injection
- **Audit logging** of all operations

## Troubleshooting

| Problem                          | Solution                              |
| -------------------------------- | ------------------------------------- |
| "Clipboard unavailable" on Linux | Install `xclip` or `xsel`             |
| OpenSSL not found                | Set `OPENSSL_ROOT_DIR` in CMake       |
| Build fails on Windows           | Ensure OpenSSL path is in system PATH |

### Setting OpenSSL Path (if needed)

```bash
cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
```

Windows example:

```cmd
cmake .. -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
```
