/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
 * system designed for modern distributed environments. It provides a
 * cryptographically anchored notion of time that can be aligned,
 * audited, and shared across domains without requiring centralized
 * trust.
 *
 * This project also includes the Aegis Semantic Passport components,
 * which complement Quorum Time by offering structured, verifiable
 * identity and capability attestations for agents and services.
 *
 * Core capabilities:
 *   - BFT Quorum Time: multi-authority, tamper-evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross-domain alignment (AlignTime).
 *
 *   - Transparency Logging: append-only, hash-chained audit records
 *                           for time events, alignment proofs, and
 *                           key-rotation operations.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security-critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open-source project with a focus on
 * clarity, auditability, and long-term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community-driven evolution of verifiable time and
 * distributed trust standards.
 */
#include "uml001/stages/quarantine_stage.h"

#include "uml001/crypto_utils.h"

namespace uml001 {

QuarantineStage::QuarantineStage(ColdVault* vault)
    : vault_(vault) {}

void QuarantineStage::execute(EventContext& ctx)
{
    if (!ctx.aborted || !vault_) {
        return;
    }
    if (ctx.audit_reason == "quarantine_logged") {
        return;
    }

    std::string serialized;
    (void)ctx.event.SerializeToString(&serialized);

    vault_->log_security_event(
        "pipeline.quarantine",
        "event_id=" + ctx.event.event_id() +
            " reason=" + (ctx.audit_reason.empty() ? std::string("unknown") : ctx.audit_reason) +
            " payload_sha256=" + sha256_hex(serialized));
    ctx.audit_reason = "quarantine_logged";
}

} // namespace uml001
