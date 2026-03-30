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
import shutil

def run_warm_boot_demo():
    # 1. Setup persistence directory
    vault_dir = os.path.join(os.getcwd(), "vault_storage")
    if not os.path.exists(vault_dir):
        os.makedirs(vault_dir)
    
    # We use a specific log file for the backend
    log_file = os.path.join(vault_dir, "vault.log")
    
    print(f"--- 🛠️  Initializing Components ---")
    
    # 2. Initialize Core Hardware/OS Abstractions
    os_clock = uml001.OsStrongClock()
    hash_p = uml001.SimpleHashProvider()
    backend = uml001.SimpleFileVaultBackend(log_file)
    
    vault_cfg = uml001.ColdVaultConfig()
    vault_cfg.base_directory = vault_dir
    
    # 3. Restore the Vault
    vault = uml001.ColdVault(vault_cfg, backend, os_clock, hash_p)
    
    # Handle the case where load_last_drift() returns None (std::optional)
    raw_drift = vault.load_last_drift()
    last_drift = raw_drift if raw_drift is not None else 0
    
    print(f"✅ Vault Loaded. Last Persisted Drift: {last_drift} ppm")

    # 4. Configure BFT Logic
    authorities = {"time-a.nist.gov", "time-b.nist.gov", "pool.ntp.org"}
    bft_cfg = uml001.BftClockConfig()
    bft_cfg.min_quorum = 2
    bft_cfg.max_total_drift = 500 
    
    bft = uml001.BFTQuorumTrustedClock(bft_cfg, authorities, vault)

    print(f"\n--- 🕒 Observing Clock Output (Live) ---")
    print(f"{'System Time (Local)':<25} | {'BFT Adjusted Time':<25} | {'Uncertainty'}")
    print("-" * 80)

    try:
        for _ in range(5):
            # Get raw system time
            sys_now = int(time.time())
            
            # FIX: Use now_unix() as defined in uml001_bindings.cpp
            bft_now = bft.now_unix()
            uncertainty = bft.get_current_uncertainty()

            print(f"{sys_now:<25} | {bft_now:<25} | ±{uncertainty:.6f}s")
            
            time.sleep(1)
            
        # 5. Update state to demonstrate persistence for the NEXT run
        print(f"\n--- 🔄 Updating Vault State ---")
        new_simulated_drift = last_drift + 10
        vault.save_last_drift(new_simulated_drift)
        print(f"Saved {new_simulated_drift} ppm to Vault. Run this script again to see it load!")
        
    except Exception as e:
        print(f"❌ Error during execution: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_warm_boot_demo()