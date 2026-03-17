#pragma once
#include "crypto_interfaces.h"
#include <fstream>

namespace uml001 {

class RotationSigner {
public:
    RotationSigner(ISignProvider& signer)
        : signer_(signer) {}

    void sign_file_root(const std::string& file_path,
                        const std::string& merkle_root)
    {
        std::vector<uint8_t> data(merkle_root.begin(), merkle_root.end());
        auto sig = signer_.sign(data);

        std::ofstream sig_file(file_path + ".sig", std::ios::binary);
        sig_file.write(reinterpret_cast<char*>(sig.data()), sig.size());
    }

private:
    ISignProvider& signer_;
};

}