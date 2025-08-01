#include <iostream>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <algorithm>
#include <string>
#include "sm3_optimized.cpp"  // 你前面的 SM3Hasher 类

using namespace std;

class MerkleTree {
private:
    SM3Hasher hasher;
    vector<array<uint8_t, 32>> leaves;
    vector<vector<array<uint8_t, 32>>> tree; // 第 i 层的节点集合

    array<uint8_t, 32> hash_leaf(const vector<uint8_t>& data) {
        vector<uint8_t> with_prefix = { 0x00 };
        with_prefix.insert(with_prefix.end(), data.begin(), data.end());
        return hasher.digest(with_prefix.data(), with_prefix.size());
    }

    array<uint8_t, 32> hash_node(const array<uint8_t, 32>& left, const array<uint8_t, 32>& right) {
        vector<uint8_t> combined = { 0x01 };
        combined.insert(combined.end(), left.begin(), left.end());
        combined.insert(combined.end(), right.begin(), right.end());
        return hasher.digest(combined.data(), combined.size());
    }

public:
    // 构建 Merkle 树
    void build(const vector<vector<uint8_t>>& raw_leaves) {
        leaves.clear();
        for (const auto& leaf : raw_leaves) {
            leaves.push_back(hash_leaf(leaf));
        }

        tree.clear();
        tree.push_back(leaves); // 第0层是叶子层

        while (tree.back().size() > 1) {
            const auto& curr_level = tree.back();
            vector<array<uint8_t, 32>> next_level;

            for (size_t i = 0; i + 1 < curr_level.size(); i += 2) {
                next_level.push_back(hash_node(curr_level[i], curr_level[i + 1]));
            }
            if (curr_level.size() % 2 == 1) {
                next_level.push_back(curr_level.back()); // 不复制最后一个节点
            }

            tree.push_back(next_level);
        }
    }

    array<uint8_t, 32> get_root() {
        if (tree.empty()) return {};
        return tree.back().front();
    }

    // 获取某个叶子的存在性证明路径
    vector<array<uint8_t, 32>> get_proof(size_t index) {
        vector<array<uint8_t, 32>> path;
        size_t i = index;
        for (size_t level = 0; level < tree.size() - 1; ++level) {
            const auto& curr_level = tree[level];
            size_t sibling = (i % 2 == 0) ? i + 1 : i - 1;
            if (sibling < curr_level.size()) {
                path.push_back(curr_level[sibling]);
            }
            i /= 2;
        }
        return path;
    }

    // 验证存在性证明
    bool verify_inclusion(const array<uint8_t, 32>& leaf_hash,
        size_t index,
        const vector<array<uint8_t, 32>>& proof,
        const array<uint8_t, 32>& root) {
        array<uint8_t, 32> computed = leaf_hash;
        size_t i = index;

        for (const auto& sibling : proof) {
            if (i % 2 == 0) {
                computed = hash_node(computed, sibling);
            }
            else {
                computed = hash_node(sibling, computed);
            }
            i /= 2;
        }

        return computed == root;
    }

    // 获取非存在性证明：返回 [前一个叶子, 当前叶子] 的哈希
    pair<vector<array<uint8_t, 32>>, vector<array<uint8_t, 32>>>
        get_non_inclusion_proof(const vector<uint8_t>& query_data) {
        array<uint8_t, 32> target_hash = hash_leaf(query_data);
        auto it = lower_bound(leaves.begin(), leaves.end(), target_hash,
            [](const array<uint8_t, 32>& a, const array<uint8_t, 32>& b) {
                return memcmp(a.data(), b.data(), 32) < 0;
            });

        size_t idx = distance(leaves.begin(), it);
        vector<array<uint8_t, 32>> left_proof, right_proof;

        if (idx > 0) {
            left_proof = get_proof(idx - 1);
        }
        if (idx < leaves.size()) {
            right_proof = get_proof(idx);
        }

        return { left_proof, right_proof };
    }
};
/*
int main() {
    MerkleTree tree;
    SM3Hasher hasher;
    vector<vector<uint8_t>> data;

    for (int i = 0; i < 100000; ++i) {
        string s = "data_" + to_string(i);
        data.push_back(vector<uint8_t>(s.begin(), s.end()));
    }

    cout << "构建树中..." << endl;
    tree.build(data);

    array<uint8_t, 32> root = tree.get_root();
    cout << "树根: ";
    for (auto b : root) printf("%02x", b);
    cout << endl;

    size_t index = 23333;
    auto leaf_hash = hasher.digest((uint8_t*)"data_23333", strlen("data_23333"));
    auto proof = tree.get_proof(index);

    bool ok = tree.verify_inclusion(leaf_hash, index, proof, root);
    cout << "存在性证明验证: " << (ok ? "失败" : "成功") << endl;

    vector<uint8_t> not_exist_data = { 'h', 'e', 'l', 'l', 'o' };
    auto [left, right] = tree.get_non_inclusion_proof(not_exist_data);
    cout << "非存在性证明（左右兄弟数量）: " << left.size() << ", " << right.size() << endl;
}*/