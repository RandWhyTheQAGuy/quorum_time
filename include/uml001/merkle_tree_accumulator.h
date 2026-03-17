#pragma once
#include "crypto_interfaces.h"
#include <vector>

namespace uml001 {

class MerkleAccumulator {
public:
    explicit MerkleAccumulator(IHashProvider& hash)
        : hash_(hash) {}

    void add_leaf(const std::string& data) {
        leaves_.push_back(hash_.sha256(data));
    }

    std::string root() {
        if (leaves_.empty()) return "EMPTY";

        std::vector<std::string> level = leaves_;
        while (level.size() > 1) {
            std::vector<std::string> next;
            for (size_t i = 0; i < level.size(); i += 2) {
                if (i + 1 < level.size())
                    next.push_back(hash_.sha256(level[i] + level[i+1]));
                else
                    next.push_back(level[i]);
            }
            level = next;
        }
        return level[0];
    }

private:
    IHashProvider& hash_;
    std::vector<std::string> leaves_;
};

}