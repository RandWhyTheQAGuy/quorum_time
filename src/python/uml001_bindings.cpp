/*
 * Quorum Time — Open Trusted Time & Distributed Verification Framework
 * Copyright 2026 Randy Spickler (github.com/RandWhyTheQAGuy)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Quorum Time is an open, verifiable, Byzantine‑resilient trusted‑time
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
 *   - BFT Quorum Time: multi‑authority, tamper‑evident time agreement
 *                      with drift bounds, authority attestation, and
 *                      cross‑domain alignment (AlignTime).
 *
 *   - Transparency Logging: append‑only, hash‑chained audit records
 *                           for time events, alignment proofs, and
 *                           key‑rotation operations.
 *
 *   - Semantic Passports: optional identity and capability metadata
 *                         for systems that require verifiable agent
 *                         provenance and authorization context.
 *
 *   - Open Integration: designed for interoperability with distributed
 *                       systems, security‑critical infrastructure,
 *                       autonomous agents, and research environments.
 *
 * Quorum Time is developed as an open‑source project with a focus on
 * clarity, auditability, and long‑term maintainability. Contributions,
 * issue reports, and discussions are welcome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * This implementation is intended for open research, practical
 * deployment, and community‑driven evolution of verifiable time and
 * distributed trust standards.
 */
// src/python/uml001_bindings.cpp
#include <memory>
#include <unordered_set>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include <pybind11/functional.h>
#include <pybind11/stl/filesystem.h>
#include "uml001/strong_clock.h"
#include "uml001/vault.h"
#include "uml001/simple_file_vault_backend.h"
#include "uml001/hash_provider.h"
#include "uml001/simple_hash_provider.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/key_rotation_manager.h"
#include "uml001/crypto_utils.h"
#include "uml001/crypto_mode.h"

namespace py = pybind11;
using namespace uml001;

// ------------------------------------------------------------
// Trampolines for abstract interfaces
// ------------------------------------------------------------
class PyIVaultBackend : public IVaultBackend {
public:
    using IVaultBackend::IVaultBackend;

    void append_line(const std::string& line) override {
        PYBIND11_OVERRIDE_PURE(void, IVaultBackend, append_line, line);
    }

    std::optional<std::string> read_last_line() override {
        PYBIND11_OVERRIDE_PURE(std::optional<std::string>, IVaultBackend, read_last_line);
    }

    void rotate() override {
        PYBIND11_OVERRIDE_PURE(void, IVaultBackend, rotate);
    }
};

class PyIHashProvider : public IHashProvider {
public:
    using IHashProvider::IHashProvider;

    std::string sha256(const std::string& data) override {
        PYBIND11_OVERRIDE_PURE(std::string, IHashProvider, sha256, data);
    }
};

// ------------------------------------------------------------
// Module
// ------------------------------------------------------------
PYBIND11_MODULE(_uml001, m) {
    m.doc() = "uml001 core bindings";

    // --------------------------------------------------------
    // Strong clock
    // --------------------------------------------------------
    py::class_<IStrongClock, std::shared_ptr<IStrongClock>>(m, "IStrongClock")
        .def("now_unix", &IStrongClock::now_unix)
        .def("get_current_drift", &IStrongClock::get_current_drift);

    py::class_<OsStrongClock, IStrongClock, std::shared_ptr<OsStrongClock>>(m, "OsStrongClock")
        .def(py::init<>());

    // --------------------------------------------------------
    // Hash provider
    // --------------------------------------------------------
    py::class_<IHashProvider, PyIHashProvider, std::shared_ptr<IHashProvider>>(m, "IHashProvider")
        .def(py::init<>())
        .def("sha256", &IHashProvider::sha256);

    py::class_<SimpleHashProvider, IHashProvider, std::shared_ptr<SimpleHashProvider>>(m, "SimpleHashProvider")
        .def(py::init<>());

    // --------------------------------------------------------
    // Vault backend
    // --------------------------------------------------------
    py::class_<IVaultBackend, PyIVaultBackend, std::shared_ptr<IVaultBackend>>(m, "IVaultBackend")
        .def(py::init<>())
        .def("append_line", &IVaultBackend::append_line)
        .def("read_last_line", &IVaultBackend::read_last_line)
        .def("rotate", &IVaultBackend::rotate);

    py::class_<SimpleFileVaultBackend, IVaultBackend, std::shared_ptr<SimpleFileVaultBackend>>(m, "SimpleFileVaultBackend")
        .def(py::init<const std::filesystem::path&>(), py::arg("path"));

    // --------------------------------------------------------
    // ColdVault::Config
    // --------------------------------------------------------
    py::class_<ColdVault::Config>(m, "ColdVaultConfig")
        .def(py::init<>())
        .def_readwrite("base_directory", &ColdVault::Config::base_directory)
        .def_readwrite("max_file_size_bytes", &ColdVault::Config::max_file_size_bytes)
        .def_readwrite("max_file_age_seconds", &ColdVault::Config::max_file_age_seconds);

    // --------------------------------------------------------
    // ColdVault
    // py::dynamic_attr() is essential for your Python test fixture!
    // --------------------------------------------------------
    py::class_<ColdVault, std::shared_ptr<ColdVault>>(m, "ColdVault", py::dynamic_attr())
        .def(py::init<
                 const ColdVault::Config&,
                 std::shared_ptr<IVaultBackend>,
                 IStrongClock&,
                 IHashProvider&>(),
             py::arg("config"),
             py::arg("backend"),
             py::arg("clock"),
             py::arg("hash_provider"))
        // We bind this as a property so real_vault.config.base_directory works in Python
        .def_property_readonly("config", &ColdVault::config, py::return_value_policy::reference_internal)
        .def("save_last_drift", &ColdVault::save_last_drift)
        .def("load_last_drift", &ColdVault::load_last_drift)
        .def("save_authority_sequences", &ColdVault::save_authority_sequences)
        .def("load_authority_sequences", &ColdVault::load_authority_sequences)
        .def("log_sync_event", &ColdVault::log_sync_event)
        .def("log_security_event", &ColdVault::log_security_event)
        .def("log_key_rotation_event", &ColdVault::log_key_rotation_event);

    // --------------------------------------------------------
    // BFT clock
    // --------------------------------------------------------
    py::class_<BftClockConfig>(m, "BftClockConfig")
        .def(py::init<>())
        .def_readwrite("min_quorum", &BftClockConfig::min_quorum)
        .def_readwrite("max_total_drift", &BftClockConfig::max_total_drift)
        .def_readwrite("max_drift_step", &BftClockConfig::max_drift_step)
        .def_readwrite("max_cluster_skew", &BftClockConfig::max_cluster_skew)
        .def_readwrite("fail_closed", &BftClockConfig::fail_closed);

    py::class_<BftSyncResult>(m, "BftSyncResult")
        .def(py::init<>())
        .def_readwrite("agreed_time", &BftSyncResult::agreed_time)
        .def_readwrite("drift_step", &BftSyncResult::drift_step)
        .def_readwrite("applied_drift", &BftSyncResult::applied_drift)
        .def_readwrite("clustered_count", &BftSyncResult::clustered_count)
        .def_readwrite("discarded_count", &BftSyncResult::discarded_count)
        .def_readwrite("warp_score_bucket", &BftSyncResult::warp_score_bucket)
        .def_readwrite("accepted_sources", &BftSyncResult::accepted_sources)
        .def_readwrite("rejected_sources", &BftSyncResult::rejected_sources)
        .def_readwrite("outliers_ejected", &BftSyncResult::outliers_ejected);

    py::class_<BFTQuorumTrustedClock, IStrongClock, std::shared_ptr<BFTQuorumTrustedClock>>(m, "BFTQuorumTrustedClock")
        .def(py::init<
                 BftClockConfig,
                 std::unordered_set<std::string>,
                 std::shared_ptr<ColdVault>>(),
             py::arg("config"),
             py::arg("trusted_authorities"),
             py::arg("audit_vault"))
        .def("now_unix", &BFTQuorumTrustedClock::now_unix)
        .def("get_current_drift", &BFTQuorumTrustedClock::get_current_drift)
        .def("get_current_uncertainty", &BFTQuorumTrustedClock::get_current_uncertainty)
        .def("update_and_sync",
             &BFTQuorumTrustedClock::update_and_sync,
             py::arg("observations"),
             py::arg("current_warp_score") = 0.0)
        .def("apply_shared_state",
             &BFTQuorumTrustedClock::apply_shared_state,
             py::arg("agreed_time"),
             py::arg("drift"),
             py::arg("leader_ts"),
             py::arg("sig"),
             py::arg("leader_id"),
             py::arg("key_id"),
             py::arg("version"),
             py::arg("warp_score"))
        .def("verify_observation", &BFTQuorumTrustedClock::verify_observation);

    // --------------------------------------------------------
    // NTP observation fetcher
    // --------------------------------------------------------
    py::class_<NtpServerEntry>(m, "NtpServerEntry")
        .def(py::init<>())
        .def_readwrite("hostname", &NtpServerEntry::hostname)
        .def_readwrite("timeout_ms", &NtpServerEntry::timeout_ms)
        .def_readwrite("max_delay_ms", &NtpServerEntry::max_delay_ms);

    py::class_<NtpObservation>(m, "NtpObservation")
        .def(py::init<>())
        .def_readwrite("server_hostname", &NtpObservation::server_hostname)
        .def_readwrite("unix_seconds", &NtpObservation::unix_seconds)
        .def_readwrite("rtt_ms", &NtpObservation::rtt_ms)
        .def_readwrite("stratum", &NtpObservation::stratum)
        .def_readwrite("is_outlier", &NtpObservation::is_outlier);

    py::class_<TimeObservation>(m, "TimeObservation")
        .def(py::init<>())
        .def_readwrite("server_hostname", &TimeObservation::server_hostname)
        .def_readwrite("key_id", &TimeObservation::key_id)
        .def_readwrite("unix_seconds", &TimeObservation::unix_seconds)
        .def_readwrite("signature_hex", &TimeObservation::signature_hex)
        .def_readwrite("sequence", &TimeObservation::sequence);

    py::class_<TimestampAttestationToken>(m, "TimestampAttestationToken")
        .def(py::init<>())
        .def_readwrite("unix_time", &TimestampAttestationToken::unix_time)
        .def_readwrite("median_rtt_ms", &TimestampAttestationToken::median_rtt_ms)
        .def_readwrite("drift_ppm", &TimestampAttestationToken::drift_ppm)
        .def_readwrite("servers", &TimestampAttestationToken::servers)
        .def_readwrite("quorum_hash_hex", &TimestampAttestationToken::quorum_hash_hex)
        .def_readwrite("signature_hex", &TimestampAttestationToken::signature_hex);

    py::class_<NtpObservationFetcher, std::shared_ptr<NtpObservationFetcher>>(m, "NtpObservationFetcher")
        .def(py::init<
                 const std::string&,
                 const std::string&,
                 const std::vector<NtpServerEntry>&,
                 std::size_t,
                 std::uint32_t,
                 std::uint32_t>(),
             py::arg("hmac_key"),
             py::arg("key_id"),
             py::arg("servers"),
             py::arg("quorum_size"),
             py::arg("timeout_ms"),
             py::arg("max_delay_ms"))
        .def("set_hmac_key", &NtpObservationFetcher::set_hmac_key)
        .def("fetch", &NtpObservationFetcher::fetch)
        .def("get_active_authority_count", &NtpObservationFetcher::get_active_authority_count)
        .def("save_sequence_state", &NtpObservationFetcher::save_sequence_state)
        .def("load_sequence_state", &NtpObservationFetcher::load_sequence_state);

    // --------------------------------------------------------
    // Crypto mode / key rotation
    // --------------------------------------------------------
    py::enum_<CryptoMode>(m, "CryptoMode")
        .value("HMAC", CryptoMode::HMAC)
        .value("ED25519", CryptoMode::ED25519);

    py::class_<KeyRotationManager::Config>(m, "KeyRotationConfig")
        .def(py::init<>())
        .def_readwrite("rotation_interval_seconds", &KeyRotationManager::Config::rotation_interval_seconds)
        .def_readwrite("overlap_window_seconds", &KeyRotationManager::Config::overlap_window_seconds);

    py::class_<KeyRotationManager, std::shared_ptr<KeyRotationManager>>(m, "KeyRotationManager")
        .def(py::init<
                 std::shared_ptr<ColdVault>,
                 const std::unordered_set<std::string>&,
                 KeyRotationManager::Config>(),
             py::arg("vault"),
             py::arg("authorities"),
             py::arg("config"))
        .def("maybe_rotate", &KeyRotationManager::maybe_rotate, py::arg("strong_time"))
        .def("configure_fetcher", &KeyRotationManager::configure_fetcher, py::arg("fetcher"))
        .def("verify_with_overlap",
             &KeyRotationManager::verify_with_overlap,
             py::arg("authority"),
             py::arg("payload"),
             py::arg("signature"),
             py::arg("strong_time"))
        .def("key_version", &KeyRotationManager::key_version)
        .def("mode", &KeyRotationManager::mode);

    // --------------------------------------------------------
    // Crypto utilities
    // --------------------------------------------------------
    m.def("sha256_hex", &sha256_hex, py::arg("input"));
    m.def("hmac_sha256_hex", &hmac_sha256_hex, py::arg("key"), py::arg("message"));
    m.def("generate_random_bytes_hex", &generate_random_bytes_hex, py::arg("byte_count"));
    m.def("register_hmac_authority",
          &register_hmac_authority,
          py::arg("authority_id"),
          py::arg("key_id"),
          py::arg("key_hex"));
}