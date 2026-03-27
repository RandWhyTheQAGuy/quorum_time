cmake_minimum_required(VERSION 3.16)
project(uml001 LANGUAGES CXX)

# Silence pybind11 warnings
if(POLICY CMP0148)
  cmake_policy(SET CMP0148 NEW)
endif()

# Homebrew discovery (Apple Silicon)
if(APPLE)
    set(HOMEBREW_PREFIX "/opt/homebrew")
    list(APPEND CMAKE_PREFIX_PATH "${HOMEBREW_PREFIX}")
    set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${HOMEBREW_PREFIX}/lib/pkgconfig")
    set(OPENSSL_ROOT_DIR "${HOMEBREW_PREFIX}/opt/openssl@3")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
find_package(pybind11 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(protobuf CONFIG REQUIRED)
find_package(Python REQUIRED COMPONENTS Interpreter Development.Module Development.Embed)
pkg_check_modules(sodium REQUIRED IMPORTED_TARGET libsodium)

# --- Protobuf/gRPC Generation ---
set(PROTO_SRC_DIR "${PROJECT_SOURCE_DIR}/proto")
set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${PROTO_OUT_DIR})

set(PROTO_FILE    "${PROTO_SRC_DIR}/clock_service.proto")
set(PROTO_PB_CPP  "${PROTO_OUT_DIR}/clock_service.pb.cc")
set(PROTO_PB_H    "${PROTO_OUT_DIR}/clock_service.pb.h")
set(GRPC_PB_CPP   "${PROTO_OUT_DIR}/clock_service.grpc.pb.cc")
set(GRPC_PB_H     "${PROTO_OUT_DIR}/clock_service.grpc.pb.h")

if(TARGET protobuf::protoc)
    set(PROTOC_EXECUTABLE $<TARGET_FILE:protobuf::protoc>)
else()
    set(PROTOC_EXECUTABLE ${Protobuf_PROTOC_EXECUTABLE})
endif()

add_custom_command(
    OUTPUT "${PROTO_PB_CPP}" "${PROTO_PB_H}" "${GRPC_PB_CPP}" "${GRPC_PB_H}"
    COMMAND ${PROTOC_EXECUTABLE}
    ARGS --cpp_out=${PROTO_OUT_DIR}
         --grpc_out=${PROTO_OUT_DIR}
         --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
         -I ${PROTO_SRC_DIR}
         ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
    COMMENT "Generating gRPC and Protobuf source files"
    VERBATIM
)

# --- Core Library ---
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
    ${PROTO_PB_CPP}
    ${GRPC_PB_CPP}
)

target_include_directories(uml001_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
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

# --- Python Module ---
if(COMMAND pybind11_add_module)
    pybind11_add_module(_uml001 src/python/uml001_bindings.cpp)
else()
    add_library(_uml001 MODULE src/python/uml001_bindings.cpp)
    set_target_properties(_uml001 PROPERTIES PREFIX "")
    target_link_libraries(_uml001 PRIVATE pybind11::module)
endif()

target_include_directories(_uml001 PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(_uml001 PRIVATE uml001_core)

# --- gRPC Aegis Server ---
add_executable(aegis_clock_server main_ntp.cpp)
target_link_libraries(aegis_clock_server PRIVATE uml001_core)
