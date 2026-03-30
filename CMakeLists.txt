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
cmake_minimum_required(VERSION 3.16)
project(uml001 LANGUAGES CXX)
option(BUILD_REST_SERVER "Build Pistache REST server binary" OFF)

if(POLICY CMP0148)
  cmake_policy(SET CMP0148 NEW)
endif()

if(APPLE)
    set(HOMEBREW_PREFIX "/opt/homebrew")
    list(APPEND CMAKE_PREFIX_PATH "${HOMEBREW_PREFIX}")
    set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${HOMEBREW_PREFIX}/lib/pkgconfig")
    set(OPENSSL_ROOT_DIR "${HOMEBREW_PREFIX}/opt/openssl@3")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(pybind11 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(protobuf CONFIG REQUIRED)
find_package(Python REQUIRED COMPONENTS Interpreter Development.Module Development.Embed)
pkg_check_modules(sodium REQUIRED IMPORTED_TARGET libsodium)
if(BUILD_REST_SERVER)
    pkg_check_modules(PISTACHE QUIET IMPORTED_TARGET libpistache)
endif()

# -----------------------
# Protobuf/gRPC Generation
# -----------------------
set(PROTO_SRC_DIR "${PROJECT_SOURCE_DIR}/proto")
set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${PROTO_OUT_DIR})

set(CLOCK_PROTO_FILE "${PROTO_SRC_DIR}/clock_service.proto")
set(CLOCK_PROTO_PB_CPP "${PROTO_OUT_DIR}/clock_service.pb.cc")
set(CLOCK_PROTO_PB_H "${PROTO_OUT_DIR}/clock_service.pb.h")
set(CLOCK_GRPC_PB_CPP "${PROTO_OUT_DIR}/clock_service.grpc.pb.cc")
set(CLOCK_GRPC_PB_H "${PROTO_OUT_DIR}/clock_service.grpc.pb.h")

set(SIGNED_STATE_PROTO_FILE "${PROTO_SRC_DIR}/signed_state.proto")
set(SIGNED_STATE_PB_CPP "${PROTO_OUT_DIR}/proto/signed_state.pb.cc")
set(SIGNED_STATE_PB_H "${PROTO_OUT_DIR}/proto/signed_state.pb.h")

if(TARGET protobuf::protoc)
    set(PROTOC_EXECUTABLE $<TARGET_FILE:protobuf::protoc>)
else()
    set(PROTOC_EXECUTABLE ${Protobuf_PROTOC_EXECUTABLE})
endif()

add_custom_command(
    OUTPUT ${CLOCK_PROTO_PB_CPP} ${CLOCK_PROTO_PB_H} ${CLOCK_GRPC_PB_CPP} ${CLOCK_GRPC_PB_H}
    COMMAND ${PROTOC_EXECUTABLE}
    ARGS --cpp_out=${PROTO_OUT_DIR}
         --grpc_out=${PROTO_OUT_DIR}
         --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
         -I ${PROTO_SRC_DIR}
         ${CLOCK_PROTO_FILE}
    DEPENDS ${CLOCK_PROTO_FILE}
)

add_custom_command(
    OUTPUT ${SIGNED_STATE_PB_CPP} ${SIGNED_STATE_PB_H}
    COMMAND ${PROTOC_EXECUTABLE}
    ARGS --cpp_out=${PROTO_OUT_DIR}
         -I ${PROJECT_SOURCE_DIR}
         ${SIGNED_STATE_PROTO_FILE}
    DEPENDS ${SIGNED_STATE_PROTO_FILE}
)

add_custom_target(signed_state_proto_gen
    DEPENDS ${SIGNED_STATE_PB_CPP} ${SIGNED_STATE_PB_H}
)

# -----------------------
# Core Library
# -----------------------
add_library(uml001_core STATIC
    src/core/bft_quorum_clock.cpp
    src/core/crypto_utils.cpp
    src/core/os_strong_clock.cpp
    src/core/simple_file_vault_backend.cpp
    src/core/cold_vault.cpp
    src/core/vault_logger.cpp
    src/core/key_rotation_manager.cpp
    src/core/ntp_observation_fetcher.cpp
    src/core/simple_hash_provider.cpp
    src/core/clock_service_impl.cpp
    src/core/quorum_time_adapter.cpp
    src/core/event_orchestrator.cpp
    src/core/pipeline_bootstrap.cpp
    src/rest/rest_handlers.cpp
    src/core/runtime_mode_machine.cpp
    src/core/pipeline_event_codec.cpp
    src/core/stages/mode_control_stage.cpp
    src/core/stages/passport_validation_stage.cpp
    src/core/stages/shared_state_ingress_stage.cpp
    src/core/stages/hitl_gate_stage.cpp
    src/core/stages/vault_stage.cpp
    src/core/stages/gossip_stage.cpp
    src/core/stages/merkle_stage.cpp
    src/core/stages/convergence_stage.cpp
    src/core/stages/recovery_stage.cpp
    src/core/stages/quorum_stage.cpp
    src/core/stages/circuit_breaker_stage.cpp
    src/core/stages/quarantine_stage.cpp
    src/gossip/default_gossip_provider.cpp
    src/gossip/GossipDedup.cpp
    ${CLOCK_PROTO_PB_CPP}
    ${CLOCK_GRPC_PB_CPP}
    ${SIGNED_STATE_PB_CPP}
)
add_dependencies(uml001_core signed_state_proto_gen)

# -----------------------
# Gossip Library (FIXED: now properly integrated)
# -----------------------
add_library(gossip
    src/gossip/GossipForwarder.cpp
    src/gossip/TTLPolicy.cpp
    src/gossip/MerkleVaultLog.cpp
    src/gossip/ConvergenceTracker.cpp
)
add_dependencies(gossip signed_state_proto_gen)

target_include_directories(gossip PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/gossip
    ${PROTO_OUT_DIR}
)

target_link_libraries(gossip PUBLIC
    OpenSSL::Crypto
    protobuf::libprotobuf
)

# 🔥 CRITICAL FIX: core now depends on gossip
target_link_libraries(uml001_core PUBLIC gossip)

target_include_directories(uml001_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/gossip
    ${PROTO_OUT_DIR}
)

target_link_libraries(uml001_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    PkgConfig::sodium
    gRPC::grpc++
    protobuf::libprotobuf
    Python::Python
)

# -----------------------
# Python Module
# -----------------------
if(COMMAND pybind11_add_module)
    pybind11_add_module(_uml001 src/python/uml001_bindings.cpp)
else()
    add_library(_uml001 MODULE src/python/uml001_bindings.cpp)
    set_target_properties(_uml001 PROPERTIES PREFIX "")
    target_link_libraries(_uml001 PRIVATE pybind11::module)
endif()

target_include_directories(_uml001 PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src/gossip
)

target_link_libraries(_uml001 PRIVATE uml001_core)

# -----------------------
# Server
# -----------------------
add_executable(aegis_clock_server main_ntp.cpp)
target_link_libraries(aegis_clock_server PRIVATE uml001_core)

if(BUILD_REST_SERVER)
    if(PISTACHE_FOUND)
        add_executable(uml001_rest_server rest/rest_server.cpp)
        target_link_libraries(uml001_rest_server PRIVATE uml001_core PkgConfig::PISTACHE)
        target_include_directories(uml001_rest_server PRIVATE ${PISTACHE_INCLUDE_DIRS})
        message(STATUS "Building uml001_rest_server (Pistache found)")
    else()
        message(WARNING "BUILD_REST_SERVER=ON but libpistache not found; skipping uml001_rest_server target")
    endif()
endif()

# -----------------------
# Tests
# -----------------------
add_executable(test_pipeline_wiring tests/test_pipeline_wiring.cpp)
target_link_libraries(test_pipeline_wiring PRIVATE uml001_core)

add_executable(test_shared_state_internal_event tests/test_shared_state_internal_event.cpp)
target_link_libraries(test_shared_state_internal_event PRIVATE uml001_core)

add_executable(test_service_ingress_pipeline tests/test_service_ingress_pipeline.cpp)
target_link_libraries(test_service_ingress_pipeline PRIVATE uml001_core)

add_executable(test_shared_state_route_contract tests/test_shared_state_route_contract.cpp)
target_link_libraries(test_shared_state_route_contract PRIVATE uml001_core)

add_executable(test_default_gossip_provider tests/test_default_gossip_provider.cpp)
target_link_libraries(test_default_gossip_provider PRIVATE uml001_core)

add_executable(test_bft_shared_state_schema_contract tests/test_bft_shared_state_schema_contract.cpp)
target_link_libraries(test_bft_shared_state_schema_contract PRIVATE uml001_core)

add_executable(test_control_plane_stages tests/test_control_plane_stages.cpp)
target_link_libraries(test_control_plane_stages PRIVATE uml001_core)

add_executable(test_schema_catalog_consistency tests/test_schema_catalog_consistency.cpp)
target_link_libraries(test_schema_catalog_consistency PRIVATE uml001_core)

add_executable(test_gossip_security_regressions tests/test_gossip_security_regressions.cpp)
target_link_libraries(test_gossip_security_regressions PRIVATE uml001_core)

add_executable(test_pipeline_codec_decode_hardening tests/test_pipeline_codec_decode_hardening.cpp)
target_link_libraries(test_pipeline_codec_decode_hardening PRIVATE uml001_core)