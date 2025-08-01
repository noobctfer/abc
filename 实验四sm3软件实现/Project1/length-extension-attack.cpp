#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <array>
#include "sm3_optimized.cpp"  

// 打印16进制函数，适用于 std::array<uint8_t, 32>
void print_hash(const std::array<uint8_t, 32>& hash) {
    for (auto b : hash) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    std::cout << std::dec << std::endl;
}
/*
int main() {
    SM3Hasher hasher;

    // 1. 原始消息
    std::string original_msg = "hello";

    // 2. 追加消息，攻击者希望追加的数据
    std::string appended_msg = "ABC";

    // 3. 计算原始消息的哈希值
    std::array<uint8_t, 32> original_hash = hasher.digest(
        reinterpret_cast<const uint8_t*>(original_msg.data()), original_msg.size());

    std::cout << "Original Hash: ";
    print_hash(original_hash);

    // 4. 从原始哈希恢复内部状态
    std::array<uint32_t, 8> state = hasher.hash_to_state(original_hash);

    // 5. 执行长度扩展攻击，继续从 state 计算追加消息的哈希
    // 注意：这里 total_original_len 必须是原始消息长度（不含填充）
    std::array<uint8_t, 32> forged_hash = hasher.continue_from_state(
        state,
        reinterpret_cast<const uint8_t*>(appended_msg.data()),
        appended_msg.size(),
        original_msg.size()
    );

    std::cout << "Forged Hash:   ";
    print_hash(forged_hash);

    // 6. 构造完整的伪造消息： original_msg + padding + appended_msg
    std::vector<uint8_t> forged_msg(
        reinterpret_cast<const uint8_t*>(original_msg.data()),
        reinterpret_cast<const uint8_t*>(original_msg.data()) + original_msg.size());

    // 计算填充，padding 函数中 total_len 默认为 msg_len 即原始消息长度
    std::vector<uint8_t> pad = hasher.padding(
        reinterpret_cast<const uint8_t*>(original_msg.data()), original_msg.size());

    forged_msg.insert(forged_msg.end(), pad.begin() + original_msg.size(), pad.end());
    // padding返回的内容包含了原始消息，这里去掉重复的部分，只插入padding及长度部分
    // padding 代码是把msg也放进去的，故这里要跳过msg部分

    // 攻击者数据
    forged_msg.insert(forged_msg.end(),
        appended_msg.begin(),
        appended_msg.end());

    // 7. 对伪造消息计算真实哈希，验证攻击成功与否
    std::array<uint8_t, 32> true_hash = hasher.digest(
        forged_msg.data(), forged_msg.size());

    std::cout << "True Hash:     ";
    print_hash(true_hash);

    if (true_hash == forged_hash) {
        std::cout << "Attack successful!" << std::endl;
    }
    else {
        std::cout << "Attack failed." << std::endl;
    }

    return 0;
}
*/