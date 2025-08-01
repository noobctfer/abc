#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <iostream>
#include <iomanip>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

class SM3Hasher {
private:
    std::array<uint32_t, 8> IV = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    std::array<uint32_t, 64> T_j;

    static inline uint32_t P0(uint32_t X) {
        return X ^ ROTL(X, 9) ^ ROTL(X, 17);
    }

    static inline uint32_t P1(uint32_t X) {
        return X ^ ROTL(X, 15) ^ ROTL(X, 23);
    }

    static inline uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, int j) {
        return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z));
    }

    static inline uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, int j) {
        return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | ((~X) & Z));
    }

    void init_T() {
        for (int j = 0; j < 64; j++) {
            uint32_t t = (j < 16) ? 0x79cc4519 : 0x7a879d8a;
            T_j[j] = ROTL(t, j % 32);
        }
    }

public:
    SM3Hasher() {
        init_T();
    }

    std::vector<uint8_t> padding(const uint8_t* msg, size_t msg_len, size_t total_len = 0) {
        uint64_t bit_len = (total_len == 0 ? msg_len : total_len) * 8;
        std::vector<uint8_t> result;
        if (msg_len > 0 && msg != nullptr)
            result.insert(result.end(), msg, msg + msg_len);

        result.push_back(0x80);
        while ((result.size() % 64) != 56) {
            result.push_back(0x00);
        }

        for (int i = 7; i >= 0; i--) {
            result.push_back((bit_len >> (8 * i)) & 0xff);
        }

        return result;
    }

    void compress(std::array<uint32_t, 8>& V, const uint8_t B[64]) {
        uint32_t W[68], W1[64];
        for (int i = 0; i < 16; i++) {
            W[i] = (B[4 * i] << 24) | (B[4 * i + 1] << 16) |
                (B[4 * i + 2] << 8) | B[4 * i + 3];
        }
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        uint32_t A = V[0], B_ = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + T_j[j]) & 0xffffffff, 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = (FF(A, B_, C, j) + D + SS2 + W1[j]) & 0xffffffff;
            uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff;

            D = C;
            C = ROTL(B_, 9);
            B_ = A;
            A = TT1;
            H = G;
            G = ROTL(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B_; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    std::array<uint8_t, 32> digest(const uint8_t* msg, size_t len) {
        std::vector<uint8_t> padded = padding(msg, len);
        std::array<uint32_t, 8> V = IV;

        for (size_t i = 0; i < padded.size(); i += 64) {
            compress(V, &padded[i]);
        }

        std::array<uint8_t, 32> result;
        for (int i = 0; i < 8; i++) {
            result[4 * i] = (V[i] >> 24) & 0xFF;
            result[4 * i + 1] = (V[i] >> 16) & 0xFF;
            result[4 * i + 2] = (V[i] >> 8) & 0xFF;
            result[4 * i + 3] = V[i] & 0xFF;
        }
        return result;
    } 

    std::array<uint32_t, 8> hash_to_state(const std::array<uint8_t, 32>& hash) {
        std::array<uint32_t, 8> V;
        for (int i = 0; i < 8; i++) {
            V[i] = (hash[4 * i] << 24) | (hash[4 * i + 1] << 16) |
                (hash[4 * i + 2] << 8) | hash[4 * i + 3];
        }
        return V;
    }

    std::array<uint8_t, 32> continue_from_state(const std::array<uint32_t, 8>& state,
        const uint8_t* append_data,
        size_t append_len,
        size_t total_original_msg_len) {
        // 计算真正原始消息长度 + 填充后的实际长度（单位：字节）
        size_t forged_total_len = ((total_original_msg_len + 1 + 8 + 63) / 64) * 64;
        size_t new_total_len = forged_total_len + append_len;

        // 只填充新数据，不再补长度
        std::vector<uint8_t> padded = padding(append_data, append_len, new_total_len);
        std::array<uint32_t, 8> V = state;

        for (size_t i = 0; i < padded.size(); i += 64) {
            compress(V, &padded[i]);
        }

        std::array<uint8_t, 32> result;
        for (int i = 0; i < 8; i++) {
            result[4 * i] = (V[i] >> 24) & 0xFF;
            result[4 * i + 1] = (V[i] >> 16) & 0xFF;
            result[4 * i + 2] = (V[i] >> 8) & 0xFF;
            result[4 * i + 3] = V[i] & 0xFF;
        }
        return result;
    }
};
