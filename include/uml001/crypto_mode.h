#pragma once

#include <string>

enum class CryptoMode {
    HMAC,
    ED25519,
    TPM_SEALED_ED25519
};

struct CryptoConfig {
    CryptoMode mode = CryptoMode::HMAC;
    std::string tpm_key_label;     // Used only in TPM mode
};