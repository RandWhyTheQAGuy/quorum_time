#pragma once

#include <string>

std::pair<std::string,std::string> generate_ed25519_keypair();

std::string ed25519_sign(
    const std::string& private_key,
    const std::string& message
);

bool ed25519_verify(
    const std::string& public_key,
    const std::string& message,
    const std::string& signature
);

// TPM wrapper (private key never leaves TPM)
std::string tpm_sign(
    const std::string& tpm_key_label,
    const std::string& message
);

bool tpm_verify(
    const std::string& public_key,
    const std::string& message,
    const std::string& signature
);