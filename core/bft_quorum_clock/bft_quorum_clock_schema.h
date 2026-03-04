#pragma once

/**
 * bft_quorum_clock_schema.h
 *
 * JSON Schema definitions for BFTQuorumTrustedClock.
 *
 * Conforms to: JSON Schema Draft 2020-12
 *
 * Intended Usage:
 *  - API boundary validation
 *  - Cross-node sync payload validation
 *  - Vault serialization format enforcement
 *  - Distributed state exchange contracts
 *
 * NOTE:
 * This file provides raw JSON schema strings.
 * These can be consumed by a JSON validation library at runtime.
 */

#include <string>

namespace uml001::schema {

static const char* JSON_SCHEMA_VERSION = "2020-12";

/**
 * TimeObservation Schema
 *
 * Canonical payload:
 * authority_id|timestamp|sequence
 */
static const char* TIME_OBSERVATION_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:TimeObservation",
  "title": "TimeObservation",
  "type": "object",
  "required": ["authority_id", "timestamp", "signature", "sequence"],
  "properties": {
    "authority_id": {
      "type": "string",
      "minLength": 1,
      "maxLength": 128,
      "pattern": "^[A-Za-z0-9._:-]+$"
    },
    "timestamp": {
      "type": "integer",
      "minimum": 0,
      "description": "Unix epoch time in seconds"
    },
    "sequence": {
      "type": "integer",
      "minimum": 0,
      "description": "Monotonic sequence number for replay protection"
    },
    "signature": {
      "type": "string",
      "minLength": 64,
      "description": "Cryptographic signature over canonical payload"
    }
  },
  "additionalProperties": false
}
)json";

/**
 * BFT Clock Configuration Schema
 */
static const char* BFT_CONFIG_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:Config",
  "title": "BFTQuorumTrustedClockConfig",
  "type": "object",
  "required": [
    "min_quorum",
    "max_cluster_skew",
    "max_drift_step",
    "max_total_drift",
    "fail_closed"
  ],
  "properties": {
    "min_quorum": {
      "type": "integer",
      "minimum": 1
    },
    "max_cluster_skew": {
      "type": "integer",
      "minimum": 0,
      "description": "Maximum allowable cluster skew in seconds"
    },
    "max_drift_step": {
      "type": "integer",
      "minimum": 0,
      "description": "Maximum drift adjustment per sync cycle (seconds)"
    },
    "max_total_drift": {
      "type": "integer",
      "minimum": 0,
      "description": "Absolute drift ceiling from OS clock (seconds)"
    },
    "fail_closed": {
      "type": "boolean"
    }
  },
  "additionalProperties": false
}
)json";

/**
 * BFT Sync Result Schema
 */
static const char* BFT_SYNC_RESULT_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:BftSyncResult",
  "title": "BftSyncResult",
  "type": "object",
  "required": [
    "agreed_time",
    "applied_drift",
    "accepted_sources",
    "outliers_ejected",
    "rejected_sources"
  ],
  "properties": {
    "agreed_time": {
      "type": "integer",
      "minimum": 0
    },
    "applied_drift": {
      "type": "integer",
      "description": "Drift step applied during this sync"
    },
    "accepted_sources": {
      "type": "integer",
      "minimum": 0
    },
    "outliers_ejected": {
      "type": "integer",
      "minimum": 0
    },
    "rejected_sources": {
      "type": "integer",
      "minimum": 0
    }
  },
  "additionalProperties": false
}
)json";

/**
 * Shared State Propagation Schema
 *
 * Used in apply_shared_state()
 */
static const char* BFT_SHARED_STATE_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:SharedState",
  "title": "BFTSharedState",
  "type": "object",
  "required": [
    "shared_agreed_time",
    "shared_applied_drift",
    "leader_system_time_at_sync"
  ],
  "properties": {
    "shared_agreed_time": {
      "type": "integer",
      "minimum": 0
    },
    "shared_applied_drift": {
      "type": "integer"
    },
    "leader_system_time_at_sync": {
      "type": "integer",
      "minimum": 0
    }
  },
  "additionalProperties": false
}
)json";

/**
 * Vault Audit Log Entry Schema
 *
 * Used for log_sync_event()
 */
static const char* BFT_VAULT_LOG_SCHEMA = R"json(
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:uml001:bft:VaultLogEntry",
  "title": "BFTVaultLogEntry",
  "type": "object",
  "required": [
    "event_type",
    "agreed_time",
    "drift_step",
    "current_drift",
    "logged_at"
  ],
  "properties": {
    "event_type": {
      "type": "string",
      "enum": ["BFT_SYNC"]
    },
    "agreed_time": {
      "type": "integer",
      "minimum": 0
    },
    "drift_step": {
      "type": "integer"
    },
    "current_drift": {
      "type": "integer"
    },
    "logged_at": {
      "type": "integer",
      "minimum": 0,
      "description": "Vault write timestamp (Unix seconds)"
    }
  },
  "additionalProperties": false
}
)json";

} // namespace uml001::schema