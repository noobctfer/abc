// SM4-GCM Optimized Implementation (Simplified for clarity)
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <iostream>

// 调用sm4_base.cpp实现的函数
extern void sm4_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint32_t round_keys[32]);
extern void sm4_key_schedule(const uint8_t key[16], uint32_t round_keys[32]);

// GF(2^128) multiplication for GHASH (simplified, portable)
static void ghash_mul(uint8_t* X, const uint8_t* H) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    memcpy(V, H, 16);

    for (int i = 0; i < 128; ++i) {
        int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
        if (bit) {
            for (int j = 0; j < 16; ++j)
                Z[j] ^= V[j];
        }

        // V = multiply by x in GF(2^128) with reduction polynomial 0xE1
        int carry = 0;
        for (int j = 15; j >= 0; --j) {
            int next = (V[j] & 1) ? 0xE1 : 0x00;
            V[j] = (V[j] >> 1) | (carry << 7);
            carry = V[j] & 1;
            if (j == 15) V[j] ^= next;
        }
    }

    memcpy(X, Z, 16);
}

// GHASH function for authentication
void ghash(const uint8_t* H, const std::vector<uint8_t>& aad, const std::vector<uint8_t>& ciphertext, uint8_t tag[16]) {
    uint8_t Y[16] = { 0 };

    for (size_t i = 0; i < aad.size(); i += 16) {
        uint8_t block[16] = { 0 };
        size_t len = std::min<size_t>(16, aad.size() - i);
        memcpy(block, &aad[i], len);
        for (int j = 0; j < 16; ++j) Y[j] ^= block[j];
        ghash_mul(Y, H);
    }

    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        uint8_t block[16] = { 0 };
        size_t len = std::min<size_t>(16, ciphertext.size() - i);
        memcpy(block, &ciphertext[i], len);
        for (int j = 0; j < 16; ++j) Y[j] ^= block[j];
        ghash_mul(Y, H);
    }

    uint64_t aad_len_bits = aad.size() * 8;
    uint64_t ct_len_bits = ciphertext.size() * 8;
    uint8_t len_block[16] = { 0 };
    for (int i = 0; i < 8; ++i) len_block[7 - i] = (aad_len_bits >> (i * 8)) & 0xff;
    for (int i = 0; i < 8; ++i) len_block[15 - i] = (ct_len_bits >> (i * 8)) & 0xff;
    for (int j = 0; j < 16; ++j) Y[j] ^= len_block[j];
    ghash_mul(Y, H);

    memcpy(tag, Y, 16);
}

// SM4-GCM Encryption
void sm4_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12], const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad, std::vector<uint8_t>& ciphertext, uint8_t tag[16]) {
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    uint8_t H[16] = { 0 };
    sm4_encrypt_block(H, H, rk); // Generate hash subkey

    uint8_t J0[16] = { 0 };
    memcpy(J0, iv, 12);
    J0[15] = 0x01; // Append counter = 1

    uint8_t counter[16];
    memcpy(counter, J0, 16);

    ciphertext.resize(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i += 16) {
        uint8_t keystream[16];
        sm4_encrypt_block(counter, keystream, rk);

        size_t len = std::min<size_t>(16, plaintext.size() - i);
        for (size_t j = 0; j < len; ++j)
            ciphertext[i + j] = plaintext[i + j] ^ keystream[j];

        // increment counter
        for (int j = 15; j >= 12; --j)
            if (++counter[j]) break;
    }

    ghash(H, aad, ciphertext, tag);

    // Encrypt the initial counter block to finalize tag
    uint8_t S[16];
    sm4_encrypt_block(J0, S, rk);
    for (int i = 0; i < 16; ++i) tag[i] ^= S[i];
}

template<typename T>
void print_hex(const T& data) {
    for (auto b : data) printf("%02x", b);
    puts("");
}

int main() {
    uint8_t key[16] = { 0 };
    uint8_t iv[12] = { 0 };
    std::vector<uint8_t> plaintext = { 'H', 'e', 'l', 'l', 'o', ' ', 'S', 'M', '4', '-', 'G', 'C', 'M' };
    std::vector<uint8_t> aad = { 'T', 'e', 's', 't' };

    std::vector<uint8_t> ciphertext;
    uint8_t tag[16];

    sm4_gcm_encrypt(key, iv, plaintext, aad, ciphertext, tag);

    printf("Ciphertext: "); print_hex(ciphertext);
    printf("Tag:        "); print_hex(std::vector<uint8_t>(tag, tag + 16));
}
