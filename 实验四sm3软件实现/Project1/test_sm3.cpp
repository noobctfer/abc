#include "sm3_optimized.cpp"




int main() {
    const char* msg = "abc";
    SM3Hasher hasher;
    auto hash = hasher.digest(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    std::cout << "SM3(\"abc\") = ";
    for (auto b : hash) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::endl;

    return 0;
}
