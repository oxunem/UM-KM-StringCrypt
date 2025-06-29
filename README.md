# UM-KM-StringCrypt

**Secure compile-time string encryption for User Mode and Kernel Mode C++ applications (C++17+).**

---

## Overview

UM-KM-StringCrypt is a lightweight header-only C++ library designed to **encrypt string literals at compile-time** and decrypt them at runtime. It supports both **User Mode** and **Kernel Mode** environments (Windows) without relying on standard libraries (CRT/STL), making it suitable for security-sensitive applications like drivers and anti-cheat systems.

The library helps protect sensitive string data embedded in binaries by obfuscating strings during compilation, significantly complicating static analysis and reverse engineering.

---

## Features

- Compile-time string encryption using `constexpr`
- Runtime decryption on demand
- Works in **User Mode** and **Kernel Mode** (Windows)
- No dependencies on CRT or STL libraries
- Supports `char` (ASCII/UTF-8) and `wchar_t` (UTF-16) strings
- Unique per-compilation-unit encryption keys derived from compile time, line number, and macro counters
- Single-header, easy to integrate
- Requires C++17 or higher

---

## How It Works

The core is a templated `SecureString` class that:

1. **Encrypts each character** of a string literal during compilation using a complex, multi-step obfuscation algorithm based on a unique compile-time seed.
2. Stores the encrypted characters in a `constexpr` array.
3. At runtime, decrypts the string into a buffer on-demand using the inverse algorithm.
4. Provides macros `ENC_STR` and `ENC_WSTR` to simplify usage and return decrypted strings transparently.

The unique encryption key varies by compilation unit, line number, and compilation time, ensuring different builds generate different encrypted outputs for the same strings.

---

## Usage

### Integration

Simply add the `secure_string.hpp` header file to your project (e.g., place in your `include/` directory), then include it where needed:

```cpp
#include "secure_string.hpp"
