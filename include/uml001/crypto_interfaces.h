#pragma once

/**
 * @file crypto_interfaces.h
 * @brief Abstract cryptographic provider interfaces for UML-001.
 *
 * Declares the three core crypto abstraction interfaces:
 *   - IHashProvider  — SHA-256 hashing (via hash_provider.h)
 *   - ISignProvider  — asymmetric signing and verification
 *   - IAEADProvider  — authenticated encryption (AES-256-GCM)
 *
 * All interfaces are pure virtual to allow hardware-backed
 * implementations (HSM, TPM) to be substituted without changing
 * call sites.
 *
 * [FIX-20] Removed duplicate IHashProvider declaration.
 *           IHashProvider was declared both here and in hash_provider.h
 *           with identical signatures, creating an ODR hazard: any
 *           translation unit including both headers would get a
 *           redefinition error. IHashProvider is now sourced exclusively
 *           from hash_provider.h via the include below.
 */

#include <cstdint>
#include <vector>

#include "uml001/hash_provider.h"  // [FIX-20] Authoritative IHashProvider declaration

namespace uml001 {

// IHashProvider is declared in hash_provider.h and re-exported here
// so callers that include crypto_interfaces.h get the full interface
// without needing a separate include.

// ============================================================
// ISignProvider
//
// Abstract interface for asymmetric signing and verification.
// Implementations: Ed25519SoftProvider, TpmSignProvider.
// The private key must never leave the provider implementation
// (TPM implementations enforce this in hardware).
// ============================================================

class ISignProvider {
public:
    virtual ~ISignProvider() = default;

    /**
     * @brief Sign data and return the signature bytes.
     * @param data  Raw bytes to sign.
     * @return Signature bytes. Format is implementation-defined
     *         (Ed25519: 64 bytes; TPM: scheme-dependent).
     */
    virtual std::vector<uint8_t> sign(
        const std::vector<uint8_t>& data) = 0;

    /**
     * @brief Verify a signature against data.
     * @param data  Raw bytes that were signed.
     * @param sig   Signature bytes to verify.
     * @return true if the signature is valid; false otherwise.
     *         Implementations must never throw on invalid signatures —
     *         return false instead to maintain fail-safe behaviour.
     */
    virtual bool verify(
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& sig) = 0;
};

// ============================================================
// IAEADProvider
//
// Abstract interface for authenticated encryption (AES-256-GCM).
// The nonce is generated internally by the implementation and
// returned via out_nonce so the caller can store it alongside
// the ciphertext for later decryption.
// ============================================================

class IAEADProvider {
public:
    virtual ~IAEADProvider() = default;

    /**
     * @brief Encrypt plaintext with additional authenticated data.
     *
     * @param plaintext  Data to encrypt.
     * @param aad        Additional authenticated data (not encrypted,
     *                   but authenticated — e.g. a record header).
     * @param out_nonce  Output parameter: the generated nonce (12 bytes
     *                   for AES-256-GCM). Must be stored by the caller
     *                   and passed back to decrypt().
     * @return Ciphertext bytes (same length as plaintext for GCM).
     *         The GCM authentication tag is appended to the ciphertext
     *         by convention; implementations must document their format.
     */
    virtual std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad,
        std::vector<uint8_t>&       out_nonce) = 0;

    /**
     * @brief Decrypt ciphertext and verify authentication.
     *
     * @param ciphertext  Encrypted bytes (including appended GCM tag).
     * @param aad         Additional authenticated data used during encryption.
     * @param nonce       The nonce returned by the corresponding encrypt() call.
     * @return Plaintext bytes on success.
     * @throws std::runtime_error if authentication fails (tag mismatch).
     *         Callers must treat any exception as a tamper/corruption event
     *         and log it to the vault before discarding the ciphertext.
     */
    virtual std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad,
        const std::vector<uint8_t>& nonce) = 0;
};

} // namespace uml001