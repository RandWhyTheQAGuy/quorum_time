/**
 * @file bft_quorum_clock_schema.h
 * @brief JSON Schema definitions for BFTQuorumTrustedClock boundary validation.
 *
 * Conforms to: JSON Schema Draft 2020-12
 *
 * ============================================================
 * INTENDED USAGE
 * ============================================================
 *
 *  - API boundary validation (inbound observations from NtpObservationFetcher)
 *  - Cross-node sync payload validation (apply_shared_state messages)
 *  - Vault serialisation format enforcement (audit log entry structure)
 *  - Distributed state exchange contracts (BftSyncResult propagation)
 *  - Configuration validation at startup (BftClockConfig loading)
 *
 * ============================================================
 * SCHEMA INVENTORY
 * ============================================================
 *
 *  TIME_OBSERVATION_SCHEMA      — struct TimeObservation (ntp_observation_fetcher.h)
 *  BFT_CONFIG_SCHEMA            — struct BftClockConfig (bft_quorum_clock.h)
 *  BFT_SYNC_RESULT_SCHEMA       — struct BftSyncResult (bft_quorum_clock.h)
 *  BFT_SHARED_STATE_SCHEMA      — apply_shared_state() parameters
 *  BFT_VAULT_SYNC_LOG_SCHEMA    — ColdVault::log_sync_event() entries
 *  BFT_VAULT_SECURITY_SCHEMA    — ColdVault::log_security_event() entries
 *
 * ============================================================
 * CHANGES FROM ORIGINAL
 * ============================================================
 *
 * SCHEMA-H-1 (CRITICAL): TIME_OBSERVATION_SCHEMA field names corrected.
 *   The original used stale names from before the FIX-MISMATCH-A and
 *   FIX-KEY-ROT corrections:
 *     "authority_id"  -> "server_hostname"
 *     "timestamp"     -> "unix_seconds"
 *     "signature"     -> "signature_hex"
 *   AND "key_id" was entirely absent (added by FIX-KEY-ROT).
 *   A validator using the old schema against real TimeObservation JSON would
 *   reject all valid observations and accept malformed ones missing key_id.
 *   The payload comment is also corrected from:
 *     "authority_id|timestamp|sequence"
 *   to:
 *     "server_hostname|key_id|unix_seconds|sequence"
 *
 * SCHEMA-H-2: TIME_OBSERVATION_SCHEMA sequence minimum 0 -> 1.
 *   NtpObservationFetcher pre-increments before issuing; sequence=0 is never
 *   emitted and would be rejected by the BFT clock's replay window check.
 *   Enforcing minimum: 1 at the schema layer catches malformed payloads
 *   before they reach the verification logic.
 *
 * SCHEMA-H-3: TIME_OBSERVATION_SCHEMA signature_hex constraints tightened.
 *   Added maxLength: 64 (HMAC-SHA-256 hex is exactly 64 chars; larger values
 *   indicate padding, encoding errors, or payload stuffing).
 *   Added pattern: "^[0-9a-f]{64}$" (lowercase hex, matching hmac_sha256_hex
 *   output; rejects uppercase, non-hex, and wrong-length strings at the
 *   schema validation stage).
 *
 * SCHEMA-H-4/5: BFT_CONFIG_SCHEMA min constraints corrected.
 *   max_drift_step: minimum 0 -> 1.  A value of 0 silently disables drift
 *   correction entirely (every step is clamped to 0).
 *   max_total_drift: minimum 0 -> 1.  A value of 0 causes every sync round
 *   to fail the drift ceiling check, permanently breaking synchronisation.
 *   max_cluster_skew: minimum 0 -> 1.  A value of 0 rejects any cluster
 *   whose servers have even 1 second of spread, which is always true in
 *   practice for multi-server quorums.
 *
 * SCHEMA-H-6: BFT_VAULT_SECURITY_SCHEMA added.
 *   ColdVault::log_security_event() is now called for all rejection and
 *   anomaly events (FIX-BFT-SEC-7).  These produce a distinct log entry
 *   structure that was previously unschematised.
 *
 * SCHEMA-H-7: BFT_VAULT_SYNC_LOG_SCHEMA event_type enum extended.
 *   Added "BFT_SHARED_STATE_SYNC" as a second enum value to distinguish
 *   entries produced by apply_shared_state() from those produced by
 *   update_and_sync().
 *
 * SCHEMA-H-8: JSON_SCHEMA_VERSION changed to inline constexpr.
 *   The original was a file-scoped static const char*, which produces a
 *   duplicate symbol definition in every translation unit that includes this
 *   header.  inline constexpr is the correct ODR-safe form in C++17+.
 *
 * SCHEMA-H-9: BFT_VAULT_SECURITY_SCHEMA key pattern tightened.
 *   Original pattern "^bft\\.[a-z0-9_.]+$" permitted single-segment keys
 *   such as "bft.foo", which skip the required subsystem level and would
 *   pass validation for a malformed audit key.
 *   All valid keys follow the form "bft.<subsystem>.<event>" (at least two
 *   dot-separated segments after "bft."), e.g.:
 *     bft.verify.unknown_authority
 *     bft.sync.quorum_insufficient
 *     bft.shared_state.committed
 *   Updated pattern enforces this structure:
 *     "^bft\\.[a-z0-9_]+\\.[a-z0-9_.]+$"
 *   This rejects "bft.foo" while accepting all keys in the AUDIT SURFACE
 *   table in bft_quorum_clock.h.
 *
 * ============================================================
 * USAGE NOTE
 * ============================================================
 *
 * These schema strings are intended for use with a JSON Schema Draft 2020-12
 * compliant validator (e.g., nlohmann/json-schema-validator, valijson).
 * They are NOT enforced at compile time; they document the expected wire
 * format and must be applied at runtime at API boundaries.
 *
 * ============================================================
 */

#pragma once

#include <string>

namespace uml001::schema {

/**
 * @brief JSON Schema Draft version used by all schemas in this file.
 *
 * SCHEMA-H-8: Changed from `static const char*` to `inline constexpr`
 * to avoid duplicate symbol definitions when this header is included in
 * multiple translation units.
 */
inline constexpr const char* JSON_SCHEMA_VERSION = "2020-12";


// ============================================================
// TimeObservation Schema
// ============================================================

/**
 * @brief Schema for struct TimeObservation (ntp_observation_fetcher.h).
 *
 * Validates the signed observation payload passed from NtpObservationFetcher
 * to BFTQuorumTrustedClock::update_and_sync().
 *
 * SIGNING PAYLOAD (canonical, used for HMAC-SHA-256):
 *   "<server_hostname>|<key_id>|<unix_seconds>|<sequence>"
 *
 * All field names, types, and constraints mirror the C++ struct exactly.
 * Any JSON representation of a TimeObservation that passes this schema is
 * structurally eligible for BFT verification; cryptographic verification
 * is performed separately by verify_observation().
 *
 * SCHEMA-H-1: Field names corrected (authority_id->server_hostname,
 *   timestamp->unix_seconds, signature->signature_hex), key_id added.
 * SCHEMA-H-2: sequence minimum raised from 0 to 1.
 * SCHEMA-H-3: signature_hex constrained to exactly 64 lowercase hex chars.
 */
inline constexpr const char* TIME_OBSERVATION_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:TimeObservation",
  "title": "TimeObservation",
  "description": "A cryptographically signed time observation produced by NtpObservationFetcher and consumed by BFTQuorumTrustedClock. Signing payload: server_hostname|key_id|unix_seconds|sequence",
  "type": "object",
  "required": ["server_hostname", "key_id", "unix_seconds", "signature_hex", "sequence"],
  "additionalProperties": false,
  "properties": {
    "server_hostname": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[A-Za-z0-9._:-]+$",
      "description": "DNS hostname or IP literal of the NTP server. Used as the authority identity in BFT verification."
    },
    "key_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 64,
      "pattern": "^[A-Za-z0-9._-]+$",
      "description": "Identifier for the HMAC key generation used to sign this observation (e.g. 'v1', 'v2'). Included in the signing payload to support zero-downtime key rotation. Must match an entry in BFTQuorumTrustedClock's key registry."
    },
    "unix_seconds": {
      "type": "integer",
      "minimum": 1,
      "description": "Unix epoch time in whole seconds as reported by the NTP server, after RTT correction and outlier filtering. Minimum 1 excludes the pre-epoch sentinel value 0."
    },
    "sequence": {
      "type": "integer",
      "minimum": 1,
      "description": "Monotonically increasing per-server sequence number for replay protection. NtpObservationFetcher pre-increments before use, so 0 is never a valid value. BFTQuorumTrustedClock rejects any observation whose sequence is <= the last accepted value for this authority."
    },
    "signature_hex": {
      "type": "string",
      "minLength": 64,
      "maxLength": 64,
      "pattern": "^[0-9a-f]{64}$",
      "description": "HMAC-SHA-256 of the signing payload, encoded as exactly 64 lowercase hexadecimal characters. Pattern enforces lowercase hex to match hmac_sha256_hex() output; rejects uppercase, non-hex, and wrong-length values."
    }
  }
}
)json";


// ============================================================
// BFT Clock Configuration Schema
// ============================================================

/**
 * @brief Schema for struct BftClockConfig (bft_quorum_clock.h).
 *
 * Used to validate configuration loaded from JSON at startup.
 * The standalone bft_clock_config.schema.json is authoritative for
 * external config files; this embedded copy is provided for runtime
 * validation via a schema validator library.
 *
 * All minimum values are enforced at 1 (not 0) for each numeric field.
 * A value of 0 for any of max_drift_step, max_total_drift, or
 * max_cluster_skew silently disables the corresponding safety mechanism;
 * this is treated as a configuration error.
 *
 * SCHEMA-H-4/5: min constraints corrected from 0 to 1.
 */
inline constexpr const char* BFT_CONFIG_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:Config",
  "title": "BFTQuorumTrustedClockConfig",
  "description": "Operational policy for BFTQuorumTrustedClock. All limits are enforced on every sync round.",
  "type": "object",
  "required": [
    "min_quorum",
    "max_cluster_skew",
    "max_drift_step",
    "max_total_drift",
    "fail_closed"
  ],
  "additionalProperties": false,
  "properties": {
    "min_quorum": {
      "type": "integer",
      "minimum": 1,
      "description": "Minimum verified observations for BFT sync. Values 1-3 produce F=0 (no Byzantine tolerance). Minimum meaningful value for fault tolerance is 4 (tolerates F=1). Recommended: 7 for F=2."
    },
    "max_cluster_skew": {
      "type": "integer",
      "minimum": 1,
      "description": "Maximum allowed timestamp spread (seconds) in the post-PBFT-trim cluster. 0 would reject all multi-server quorums. Recommended: 5 s."
    },
    "max_drift_step": {
      "type": "integer",
      "minimum": 1,
      "description": "Maximum drift correction (seconds) per sync round. Anti-shock limit. 0 silently disables all drift correction. Recommended: 2 s."
    },
    "max_total_drift": {
      "type": "integer",
      "minimum": 1,
      "description": "Maximum absolute cumulative drift from the OS clock (seconds). Anti-creep ceiling. 0 causes every sync to fail. Recommended: 60 s."
    },
    "fail_closed": {
      "type": "boolean",
      "description": "If true, abort() the process when max_total_drift is exceeded, after a durable ColdVault audit entry is written. Set true for HSMs and PKI services; set false for systems that prefer degraded operation."
    }
  }
}
)json";


// ============================================================
// BFT Sync Result Schema
// ============================================================

/**
 * @brief Schema for struct BftSyncResult (bft_quorum_clock.h).
 *
 * Returned by update_and_sync() on success and also recorded in the
 * vault via bft.sync.committed.  Used to validate cross-node result
 * propagation in clustered deployments.
 *
 * No changes from original — all field names and types are correct.
 */
inline constexpr const char* BFT_SYNC_RESULT_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:BftSyncResult",
  "title": "BftSyncResult",
  "description": "Result of a successful BFT synchronisation round, returned by update_and_sync().",
  "type": "object",
  "required": [
    "agreed_time",
    "applied_drift",
    "accepted_sources",
    "outliers_ejected",
    "rejected_sources"
  ],
  "additionalProperties": false,
  "properties": {
    "agreed_time": {
      "type": "integer",
      "minimum": 0,
      "description": "BFT-agreed median Unix time committed this round (seconds since epoch)."
    },
    "applied_drift": {
      "type": "integer",
      "description": "Drift adjustment applied this round (seconds). May be negative. Clamped to max_drift_step."
    },
    "accepted_sources": {
      "type": "integer",
      "minimum": 0,
      "description": "Number of observations that survived PBFT trimming and skew validation (the clustered set size: n_valid - 2*F)."
    },
    "outliers_ejected": {
      "type": "integer",
      "minimum": 0,
      "description": "Number of observations removed by PBFT trimming (F lowest + F highest = 2 * floor((n_valid-1)/3))."
    },
    "rejected_sources": {
      "type": "integer",
      "minimum": 0,
      "description": "Number of observations rejected during signature, replay-window, or whitelist verification before PBFT trimming."
    }
  }
}
)json";


// ============================================================
// Shared State Propagation Schema
// ============================================================

/**
 * @brief Schema for the apply_shared_state() message payload.
 *
 * Used in clustered deployments where a leader node runs update_and_sync()
 * and follower nodes adopt the result via apply_shared_state().
 *
 * SECURITY NOTE: This schema validates structure only.  The caller must
 * authenticate the leader's message (e.g., mTLS, cluster MAC) before
 * deserialising and passing it to apply_shared_state().
 *
 * No changes from original — all field names and types are correct.
 */
inline constexpr const char* BFT_SHARED_STATE_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:SharedState",
  "title": "BFTSharedState",
  "description": "Shared-state propagation payload from a cluster leader to follower nodes. Consumed by apply_shared_state(). Must be authenticated by the caller before use.",
  "type": "object",
  "required": [
    "shared_agreed_time",
    "shared_applied_drift",
    "leader_system_time_at_sync"
  ],
  "additionalProperties": false,
  "properties": {
    "shared_agreed_time": {
      "type": "integer",
      "minimum": 0,
      "description": "Leader's BFT-agreed Unix time (seconds since epoch)."
    },
    "shared_applied_drift": {
      "type": "integer",
      "description": "Leader's drift step applied this round (seconds). Informational; not used in the follower's drift calculation."
    },
    "leader_system_time_at_sync": {
      "type": "integer",
      "minimum": 0,
      "description": "Leader's raw OS time (seconds since epoch) at the moment update_and_sync() committed. Used by the follower to extrapolate the agreed time to 'now'."
    }
  }
}
)json";


// ============================================================
// Vault Sync Log Entry Schema
// ============================================================

/**
 * @brief Schema for ColdVault::log_sync_event() audit entries.
 *
 * Covers both update_and_sync() commits (event_type: "BFT_SYNC") and
 * apply_shared_state() commits (event_type: "BFT_SHARED_STATE_SYNC").
 *
 * SCHEMA-H-7: Added "BFT_SHARED_STATE_SYNC" to the event_type enum
 * to distinguish follower adoption events from primary sync events in the
 * audit log.
 */
inline constexpr const char* BFT_VAULT_SYNC_LOG_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:VaultSyncLogEntry",
  "title": "BFTVaultSyncLogEntry",
  "description": "Audit log entry produced by ColdVault::log_sync_event() after a successful BFT sync commit or shared-state adoption.",
  "type": "object",
  "required": [
    "event_type",
    "agreed_time",
    "drift_step",
    "current_drift",
    "logged_at"
  ],
  "additionalProperties": false,
  "properties": {
    "event_type": {
      "type": "string",
      "enum": ["BFT_SYNC", "BFT_SHARED_STATE_SYNC"],
      "description": "BFT_SYNC: produced by update_and_sync(). BFT_SHARED_STATE_SYNC: produced by apply_shared_state() on a follower node."
    },
    "agreed_time": {
      "type": "integer",
      "minimum": 0,
      "description": "BFT-agreed Unix time committed this round (seconds since epoch)."
    },
    "drift_step": {
      "type": "integer",
      "description": "Drift adjustment applied this round (seconds). May be negative."
    },
    "current_drift": {
      "type": "integer",
      "description": "Cumulative drift correction after this round (seconds). May be negative."
    },
    "logged_at": {
      "type": "integer",
      "minimum": 0,
      "description": "Vault write timestamp (Unix seconds). Recorded by the ColdVault implementation at the moment of the durable write."
    }
  }
}
)json";


// ============================================================
// Vault Security Event Log Schema
// ============================================================

/**
 * @brief Schema for ColdVault::log_security_event() audit entries.
 *
 * SCHEMA-H-6: ColdVault::log_security_event() is called for all
 * security-relevant rejection and anomaly events in BFTQuorumTrustedClock.
 * These produce a distinct log entry structure from sync events.
 * This schema was absent from the original file.
 *
 * SCHEMA-H-9: key pattern tightened from "^bft\\.[a-z0-9_.]+$" to
 * "^bft\\.[a-z0-9_]+\\.[a-z0-9_.]+$" to require at least two
 * dot-separated segments after "bft." (i.e. bft.<subsystem>.<event>).
 * The original pattern permitted single-segment keys such as "bft.foo"
 * which skip the subsystem level and would pass validation for a
 * malformed audit key. All valid keys in the AUDIT SURFACE table in
 * bft_quorum_clock.h have the two-segment form; the tightened pattern
 * rejects any deviation at the schema layer before it reaches the vault.
 *
 * Event type values (matches AUDIT SURFACE in bft_quorum_clock.h):
 *   bft.cold_start.drift_clamped
 *   bft.verify.unknown_authority
 *   bft.verify.replay_detected
 *   bft.verify.sig_failed
 *   bft.sync.quorum_insufficient
 *   bft.sync.bft_bounds_failed
 *   bft.sync.cluster_skew_exceeded
 *   bft.sync.drift_ceiling_exceeded
 *   bft.sync.fail_closed_abort
 *   bft.sync.committed
 *   bft.shared_state.drift_ceiling
 *   bft.shared_state.committed
 */
inline constexpr const char* BFT_VAULT_SECURITY_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:VaultSecurityLogEntry",
  "title": "BFTVaultSecurityLogEntry",
  "description": "Audit log entry produced by ColdVault::log_security_event() for all security-relevant rejection, anomaly, and abort events in BFTQuorumTrustedClock. detail MUST NOT contain HMAC key material.",
  "type": "object",
  "required": [
    "event_type",
    "key",
    "detail",
    "logged_at"
  ],
  "additionalProperties": false,
  "properties": {
    "event_type": {
      "type": "string",
      "const": "BFT_SECURITY_EVENT",
      "description": "Fixed discriminator for security event log entries."
    },
    "key": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^bft\\.[a-z0-9_]+\\.[a-z0-9_.]+$",
      "description": "Structured event identifier in the form 'bft.<subsystem>.<event>'. At least two dot-separated segments after 'bft.' are required; single-segment keys (e.g. 'bft.foo') are rejected. Never user-controlled. See AUDIT SURFACE table in bft_quorum_clock.h for the complete list of valid keys."
    },
    "detail": {
      "type": "string",
      "minLength": 0,
      "maxLength": 1024,
      "description": "Human-readable context for the event (e.g. authority ID, sequence numbers, numeric values). MUST NOT contain HMAC key material or secrets."
    },
    "logged_at": {
      "type": "integer",
      "minimum": 0,
      "description": "Vault write timestamp (Unix seconds). Recorded by the ColdVault implementation at the moment of the durable write."
    }
  }
}
)json";

} // namespace uml001::schema