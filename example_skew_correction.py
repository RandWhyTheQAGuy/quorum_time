# Quorum Time — Open Trusted Time & Distributed Verification Framework
# Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
# SPDX-License-Identifier: Apache-2.0
#
# Quorum Time is an open, verifiable, Byzantine-resilient trusted-time
# system designed for modern distributed environments. It provides a
# cryptographically anchored notion of time that can be aligned,
# audited, and shared across domains without requiring centralized
# trust.
#
# This project also includes the Aegis Semantic Passport components,
# which complement Quorum Time by offering structured, verifiable
# identity and capability attestations for agents and services.
#
# Core capabilities:
#   - BFT Quorum Time: multi-authority, tamper-evident time agreement
#                      with drift bounds, authority attestation, and
#                      cross-domain alignment (AlignTime).
#
#   - Transparency Logging: append-only, hash-chained audit records
#                           for time events, alignment proofs, and
#                           key-rotation operations.
#
#   - Open Integration: designed for interoperability with distributed
#                       systems, security-critical infrastructure,
#                       autonomous agents, and research environments.
#
# Quorum Time is developed as an open-source project with a focus on
# clarity, auditability, and long-term maintainability. Contributions,
# issue reports, and discussions are welcome.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# This implementation is intended for open research, practical
# deployment, and community-driven evolution of verifiable time and
# distributed trust standards.
#
import uml001
import time
import os

def run_skew_demo():
    vault_dir = os.path.join(os.getcwd(), "vault_storage_skew")
    if not os.path.exists(vault_dir):
        os.makedirs(vault_dir)
    
    log_file = os.path.join(vault_dir, "vault.log")
    
    # 1. Setup Core Components
    os_clock = uml001.OsStrongClock()
    hash_p = uml001.SimpleHashProvider()
    backend = uml001.SimpleFileVaultBackend(log_file)
    vault_cfg = uml001.ColdVaultConfig()
    vault_cfg.base_directory = vault_dir
    vault = uml001.ColdVault(vault_cfg, backend, os_clock, hash_p)

    # 2. INJECT SKEW: We tell the vault the local clock is running FAST (+10,000 ppm)
    # This means for every million microseconds, the BFT clock will subtract 10,000.
    simulated_drift_ppm = 10000 
    vault.save_last_drift(simulated_drift_ppm)
    
    # 3. Initialize BFT Clock
    authorities = {"ntp-1", "ntp-2", "ntp-3"}
    bft_cfg = uml001.BftClockConfig()
    bft_cfg.min_quorum = 2
    bft = uml001.BFTQuorumTrustedClock(bft_cfg, authorities, vault)

    print(f"--- 🚀 Skew Correction Simulation ---")
    print(f"Simulated Hardware Drift: +{simulated_drift_ppm} ppm (Fast Clock)")
    print(f"BFT Clock will now apply negative compensation.\n")
    print(f"{'Real OS Time':<20} | {'BFT Adjusted Time':<20} | {'Correction (s)'}")
    print("-" * 65)

    # We capture the starting point to show the divergence
    start_os = os_clock.now_unix()
    start_bft = bft.now_unix()

    try:
        # We run this for 10 "simulated" steps. 
        # Note: To see massive divergence in 10 seconds, 10k ppm is a lot!
        for i in range(10):
            current_os = os_clock.now_unix()
            current_bft = bft.now_unix()
            
            # Calculate how much the BFT clock has "pulled back" the OS time
            # (current_os - start_os) is elapsed real time
            # (current_bft - start_bft) is elapsed adjusted time
            correction = (current_os - start_os) - (current_bft - start_bft)

            print(f"{current_os:<20} | {current_bft:<20} | {correction:+.6f}s")
            
            time.sleep(1)

        print(f"\n✅ Result: The BFT clock successfully lagged the 'fast' OS clock")
        print(f"to maintain synchronization with the cluster quorum.")

    except Exception as e:
        print(f"❌ Simulation failed: {e}")

if __name__ == "__main__":
    run_skew_demo()