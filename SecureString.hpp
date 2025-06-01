// Secure compile-time string encryption for User Mode (C++17+)
// Author: oxunem (https://github.com/oxunem)
// License: MIT

#pragma once

// ------------------------------------------------------------
// This header provides a constexpr string encryption class and
// macros for obfuscating strings at compile-time.
//
// Usage:
//    const char* secret = ENC_STR("Hello World!");
//    const wchar_t* secretW = ENC_WSTR(L"Hello World!");
//
// Works in User Mode applications, relying on <cstdint>, <cstddef>.
// ------------------------------------------------------------

#ifdef _KERNEL_MODE
#include <ntddk.h>
using uint8_t = UCHAR;
using uint64_t = ULONGLONG;
using size_t = SIZE_T;
#define FORCEINLINE __forceinline
#else
#include <cstdint>
#include <cstddef>
#define FORCEINLINE __forceinline
#endif

// Rotate left 8-bit
#define ROL8(x, r) ((uint8_t)(((x) << ((r) % 8)) | ((x) >> (8 - ((r) % 8)))))
// Rotate right 8-bit
#define ROR8(x, r) ((uint8_t)(((x) >> ((r) % 8)) | ((x) << (8 - ((r) % 8)))))

// Generate a unique seed based on compile time macros.
// Helps to have different seeds per compilation unit/line/time.
#define SECURE_UNIQUE_SEED \
    ((__LINE__ * 0xF1E2D3C4B5A69788ULL) ^ \
     (__COUNTER__ * 0x123456789ABCDEF0ULL) ^ \
     ((__TIME__[7] - '0') * 0x9A8B7C6D5E4F3210ULL) ^ \
     ((__DATE__[0] << 24) | (__DATE__[4] << 16) | (__DATE__[7] << 8)) ^ \
     ((__COUNTER__ % 256) * 0xCAFEBABEDEADBEEFULL))

// Compile-time Key Generator
template<size_t N, uint64_t Seed, size_t Round = 0>
struct KeyGen {
private:
    static constexpr uint64_t mix(uint64_t x) {
        x ^= x >> 33; x *= 0xD6E8FEB86659FD93ULL;
        x ^= x >> 33; x *= 0xA5CB3E2C1F16F4C5ULL;
        return x ^ (x >> 33);
    }

    static constexpr uint8_t get_byte(size_t index) {
        constexpr uint64_t magic = 0x3C6EF372FE94F82BULL;
        uint64_t val = Seed ^ (index * magic);
        val = mix(val) ^ (Round * 0x0F1E2D3C4B5A6978ULL);
        val = (val >> 32) ^ (val & 0xFFFFFFFF);
        return static_cast<uint8_t>((val ^ (val >> 16) ^ (val >> 8)));
    }

public:
    static constexpr uint8_t get(size_t index) {
        uint8_t k = get_byte(index) ^ get_byte(N - index - 1 + Round);
        return ROL8(k ^ index ^ (Seed & 0xFF), (index + Round) % 8 + 1);
    }
};

// SecureString encrypts characters at compile-time and decrypts at runtime
template<typename CharT, size_t N, uint64_t Seed>
class SecureString {
private:
    CharT encrypted[N];

    static constexpr CharT obfuscate(CharT c, size_t i) {
        uint8_t k1 = KeyGen<N, Seed>::get(i);
        uint8_t k2 = KeyGen<N, Seed ^ 0xBAADF00DDEADC0DEULL>::get(N - i - 1);
        uint8_t k3 = KeyGen<N, Seed ^ 0xFEEDBABECAFED00DULL>::get((i * i) % N);

        uint8_t tmp = static_cast<uint8_t>(c) ^ k1;
        tmp = ROL8(tmp, (k2 % 7) + 1);
        tmp = ~(tmp + (k2 ^ k3));
        tmp ^= 0x5A;
        tmp = ROR8(tmp, (i + k3) % 8);

        return static_cast<CharT>(tmp);
    }

    static constexpr CharT deobfuscate(CharT c, size_t i) {
        uint8_t k1 = KeyGen<N, Seed>::get(i);
        uint8_t k2 = KeyGen<N, Seed ^ 0xBAADF00DDEADC0DEULL>::get(N - i - 1);
        uint8_t k3 = KeyGen<N, Seed ^ 0xFEEDBABECAFED00DULL>::get((i * i) % N);

        uint8_t tmp = static_cast<uint8_t>(c);
        tmp = ROL8(tmp, (i + k3) % 8);
        tmp ^= 0x5A;
        tmp = ~(tmp) - (k2 ^ k3);
        tmp = ROR8(tmp, (k2 % 7) + 1);
        tmp ^= k1;

        return static_cast<CharT>(tmp);
    }

public:
    constexpr SecureString(const CharT(&input)[N]) : encrypted{} {
        for (size_t i = 0; i < N; ++i)
            encrypted[i] = obfuscate(input[i], i);
    }

    // Decrypt into out buffer (must be at least N elements)
    FORCEINLINE void decrypt(CharT* out) const {
        for (size_t i = 0; i < N; ++i)
            out[i] = deobfuscate(encrypted[i], i);
    }

    constexpr size_t size() const { return N; }
};

// Helper macro to create an encrypted const char* string.
// Usage: const char* secret = ENC_STR("Hello!");
#define ENC_STR(s) ([] { \
    static constexpr auto crypt = SecureString<char, sizeof(s), SECURE_UNIQUE_SEED>(s); \
    static char buf[sizeof(s)] = {}; \
    crypt.decrypt(buf); \
    return buf; \
}())

// Helper macro to create an encrypted const wchar_t* string.
// Usage: const wchar_t* secret = ENC_WSTR(L"Hello!");
#define ENC_WSTR(s) ([] { \
    static constexpr auto crypt = SecureString<wchar_t, sizeof(s) / sizeof(wchar_t), SECURE_UNIQUE_SEED>(s); \
    static wchar_t buf[sizeof(s) / sizeof(wchar_t)] = {}; \
    crypt.decrypt(buf); \
    return buf; \
}())

/*
MIT License

Copyright (c) 2025 oxunem

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/