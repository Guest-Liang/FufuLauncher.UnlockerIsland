#pragma once
#include <string>

class XorString {
    static constexpr char key = 0x5F;

public:
    template<size_t N>
    struct EncryptedData {
        char data[N];
    };

    template<size_t N>
    static constexpr auto encrypt(const char(&str)[N]) {
        EncryptedData<N> encrypted{};
        for (size_t i = 0; i < N; ++i) {
            encrypted.data[i] = str[i] ^ key;
        }
        return encrypted;
    }

    template<size_t N>
    static std::string decrypt(const EncryptedData<N>& encrypted) {
        std::string decrypted;
        decrypted.resize(N - 1);
        for (size_t i = 0; i < N - 1; ++i) {
            decrypted[i] = encrypted.data[i] ^ key;
        }
        return decrypted;
    }
};