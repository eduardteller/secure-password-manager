# Secure Password Manager

A secure command-line password manager built with C++.

## Features

- **Secure Encryption**: Uses modern cryptographic algorithms to protect your passwords
- **Master Password Protection**: All passwords are encrypted with a master password
- **CLI Interface**: Easy-to-use command-line interface
- **Local Storage**: Your passwords are stored locally in an encrypted vault

## Building

### Prerequisites

- CMake 3.15 or higher
- C++17 compatible compiler (GCC, Clang, or MSVC)

### Build Instructions

```bash
# Create build directory
mkdir build
cd build

# Configure
cmake ..

# Build
cmake --build .

# Run tests
ctest
```

## Usage

### Initialize a new vault

```bash
./SecurePasswordManager init
```

### Add a password

```bash
./SecurePasswordManager add
```

### Retrieve a password

```bash
./SecurePasswordManager get
```

### List all services

```bash
./SecurePasswordManager list
```

### Delete a password

```bash
./SecurePasswordManager delete
```

## Project Structure

```
secure-password-manager/
├── CMakeLists.txt          # Main CMake configuration
├── src/
│   ├── main.cpp            # Application entry point
│   ├── crypto/             # Cryptographic functions
│   │   ├── crypto.cpp
│   │   └── crypto.hpp
│   ├── storage/            # Vault storage management
│   │   ├── vault.cpp
│   │   └── vault.hpp
│   └── ui/                 # Command-line interface
│       ├── cli.cpp
│       └── cli.hpp
├── tests/                  # Unit tests
│   ├── CMakeLists.txt
│   └── test_main.cpp
└── docs/
    └── README.md
```

## Security Considerations

⚠️ **Important**: This is a basic implementation. For production use, consider:

- Using established cryptographic libraries (OpenSSL, libsodium)
- Implementing proper key derivation (PBKDF2, Argon2)
- Using authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Secure memory handling (zeroing sensitive data)
- Regular security audits

## License

TODO: Add license

## Contributing

TODO: Add contributing guidelines

