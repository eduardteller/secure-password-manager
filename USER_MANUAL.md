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

To build SPM on Windows using GCC and OpenSSL, follow these steps:

#### 1. Install MSYS2

Download and install MSYS2 from:

https://www.msys2.org/

After installation, open the terminal named:

**MSYS2 UCRT64**

#### 2. Update MSYS2

In the UCRT64 terminal:

```bash
pacman -Syu
```

Close the terminal when it tells you, then reopen MSYS2 UCRT64 and continue:

```bash
pacman -Syu
```

#### 3. Install required packages (GCC, CMake, OpenSSL)

Run in MSYS2 UCRT64:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc
pacman -S mingw-w64-ucrt-x86_64-cmake
pacman -S mingw-w64-ucrt-x86_64-openssl
pacman -S mingw-w64-ucrt-x86_64-make
```

This installs:

- GCC compiler
- CMake
- OpenSSL (libraries + headers)
- MinGW mingw32-make build tool

#### 4. Build the project with MinGW

Navigate to your project folder inside the UCRT64 terminal:

```bash
cd /c/Users/<YourUser>/Desktop/secure-password-manager-main
mkdir build
cd build
```

Run CMake:

```bash
cmake .. -G "MinGW Makefiles" -DOPENSSL_ROOT_DIR="C:/msys64/ucrt64"
```

Then compile:

```bash
mingw32-make
```

If successful, the executable will be:

```
build/spm.exe
```

## Building

### Linux & macOS

```bash
mkdir build && cd build
cmake ..
make
```

The executable `spm` will be in the `build/` folder.

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

| Problem                          | Solution                        |
| -------------------------------- | ------------------------------- |
| "Clipboard unavailable" on Linux | Install `xclip` or `xsel`       |
| OpenSSL not found                | Set `OPENSSL_ROOT_DIR` in CMake |

### Setting OpenSSL Path (if needed)

```bash
cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
```

Windows example:

```cmd
cmake .. -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
```
