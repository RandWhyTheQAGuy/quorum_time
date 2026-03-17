#pragma once

/**
 * @file crypto_utils_extensions.h
 * @brief Ed25519 and TPM signing utilities for UML-001.
 *
 * Provides software Ed25519 keypair generation, signing, and verification,
 * plus TPM-backed signing where the private key never leaves the TPM.
 *
 * All functions are in namespace uml001 for consistency with the rest
 * of the codebase and to avoid name collisions with other crypto libraries
 * (e.g. libsodium, OpenSSL) that may expose identically-named symbols at
 * global scope.
 *
 * [FIX-21] Wrapped all declarations in namespace uml001.
 *           The original file declared all functions at global scope,
 *           inconsistent with every other header in this project and
 *           creating a risk of name collisions with third-party crypto
 *           libraries. All call sites must be updated to use the
 *           uml001:: prefix or a using declaration.
 *
 * Key format convention:
 *   All keys are passed and returned as std::string containing raw binary
 *   key material (not hex or base64 encoded). Callers are responsible for
 *   secure storage and zeroing of key material after use.
 *
 * TPM note:
 *   tpm_sign() uses a key identified by label; the private key never
 *   leaves the TPM boundary. tpm_verify() uses a public key exported
 *   from the TPM at provisioning time.
 */

#include <string>

namespace uml001 {

// ============================================================
// Ed25519 Software Implementation
// ============================================================

/**
 * @brief Generate an Ed25519 keypair.
 *
 * @return Pair of (private_key, public_key) as raw binary strings.
 *         private_key: 64 bytes (seed || public_key in libsodium convention)
 *         public_key:  32 bytes
 *
 * WARNING: The returned private key is sensitive material. Zero it
 * from memory as soon as it is no longer needed.
 */
std::pair<std::string, std::string> generate_ed25519_keypair();

/**
 * @brief Sign a message with an Ed25519 private key.
 *
 * @param private_key  64-byte Ed25519 private key (raw binary).
 * @param message      Arbitrary message bytes to sign.
 * @return 64-byte Ed25519 signature (raw binary).
 */
std::string ed25519_sign(
    const std::string& private_key,
    const std::string& message
);

/**
 * @brief Verify an Ed25519 signature.
 *
 * @param public_key  32-byte Ed25519 public key (raw binary).
 * @param message     Message bytes that were signed.
 * @param signature   64-byte Ed25519 signature to verify.
 * @return true if the signature is valid; false otherwise.
 *         Never throws — returns false on any verification failure
 *         to maintain fail-safe behaviour.
 */
bool ed25519_verify(
    const std::string& public_key,
    const std::string& message,
    const std::string& signature
);

// ============================================================
// TPM-Backed Signing
//
// The private key never leaves the TPM boundary. tpm_sign() sends
// the message digest to the TPM and receives the signature. The
// corresponding public key is exported at provisioning time and
// used by tpm_verify() for offline verification.
// ============================================================

/**
 * @brief Sign a message using a TPM-resident key.
 *
 * @param tpm_key_label  Platform-specific key label or handle string
 *                       identifying the TPM key to use.
 * @param message        Arbitrary message bytes to sign. The TPM
 *                       implementation hashes internally before signing.
 * @return Signature bytes in the scheme-specific format for this TPM key.
 */
std::string tpm_sign(
    const std::string& tpm_key_label,
    const std::string& message
);

/**
 * @brief Verify a TPM-generated signature using an exported public key.
 *
 * @param public_key  Public key exported from the TPM at provisioning.
 * @param message     Message bytes that were signed.
 * @param signature   Signature bytes returned by tpm_sign().
 * @return true if the signature is valid; false otherwise.
 *         Never throws — returns false on any verification failure.
 */
bool tpm_verify(
    const std::string& public_key,
    const std::string& message,
    const std::string& signature
);

} // namespace uml001