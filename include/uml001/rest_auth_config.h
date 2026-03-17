#pragma once

#include <string>
#include <vector>

/**
 * @file rest_auth_config.h
 * @brief Authentication configuration for the UML-001 Trusted Time REST API.
 *
 * SECURITY OVERVIEW
 * -----------------
 * UML-001 supports three authentication modes:
 *
 *   1. NONE
 *      - No authentication.
 *      - Only acceptable for isolated CI, local development, or air-gapped test rigs.
 *      - All requests are still logged for audit visibility.
 *
 *   2. API_KEY
 *      - Shared secret provided via HTTP header "X-API-Key".
 *      - Simple to deploy but coarse-grained.
 *      - Compromise of the key grants full access.
 *      - Must be rotated regularly and stored in a secure secret manager.
 *
 *   3. MTLS
 *      - Strongest option.
 *      - Requires TLS termination by a trusted reverse proxy (Envoy, NGINX, HAProxy)
 *        that validates client certificates and injects "X-Client-Identity".
 *      - Identity is cryptographically bound to the client certificate.
 *      - Revocation and rotation handled by PKI.
 *
 * All authentication failures are logged via ColdVault::log_security_event().
 */

namespace uml001 {

enum class RestAuthMode {
    NONE,
    API_KEY,
    MTLS
};

struct RestAuthConfig {
    RestAuthMode mode = RestAuthMode::NONE;

    // Used only in API_KEY mode.
    std::string api_key;

    // Used only in MTLS mode.
    std::vector<std::string> allowed_identities;
};

} // namespace uml001
