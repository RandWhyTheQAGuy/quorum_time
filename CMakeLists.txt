cmake_minimum_required(VERSION 3.16)
project(uml001 LANGUAGES CXX)

# ------------------------------------------------------------
# Global settings
# ------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Release)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Release)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Release)

# ------------------------------------------------------------
# Dependencies: pybind11, OpenSSL
# ------------------------------------------------------------
find_package(pybind11 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)

# ------------------------------------------------------------
# libsodium discovery (robust cross‑platform)
# ------------------------------------------------------------

pkg_check_modules(SODIUM_PKG QUIET libsodium)

if (SODIUM_PKG_FOUND)
    message(STATUS "Found libsodium via pkg-config")
    set(SODIUM_INCLUDE_DIR ${SODIUM_PKG_INCLUDE_DIRS})
    set(SODIUM_LIBRARY ${SODIUM_PKG_LIBRARIES})

    # 🔑 This is the missing piece: tell the linker where -lsodium lives
    link_directories(${SODIUM_PKG_LIBRARY_DIRS})
else()
    message(WARNING "pkg-config could not find libsodium; falling back to manual search")

    find_library(SODIUM_LIBRARY sodium
        PATHS /opt/homebrew/lib /usr/local/lib
    )

    find_path(SODIUM_INCLUDE_DIR sodium.h
        PATHS /opt/homebrew/include /usr/local/include
    )

    if (NOT SODIUM_LIBRARY)
        message(FATAL_ERROR "libsodium not found. Install with: brew install libsodium")
    endif()
endif()

message(STATUS "libsodium include dir: ${SODIUM_INCLUDE_DIR}")
message(STATUS "libsodium library: ${SODIUM_LIBRARY}")

include_directories(${SODIUM_INCLUDE_DIR})

# ------------------------------------------------------------
# Include directories
# ------------------------------------------------------------
include_directories(${PROJECT_SOURCE_DIR}/include)

# ------------------------------------------------------------
# Core C++ static library (uml001_core)
# ------------------------------------------------------------
add_library(uml001_core STATIC
    src/core/bft_quorum_clock.cpp
    src/core/crypto_utils.cpp
    src/core/file_vault_backend.cpp
    src/core/cold_vault.cpp
    src/core/main_ntp.cpp
    src/core/ntp_observation_fetcher.cpp
    src/core/vault_logger.cpp
    src/core/os_strong_clock.cpp
    src/core/simple_hash_provider.cpp
    src/core/simple_file_vault_backend.cpp
    src/core/simple_hash_provider.cpp
)

target_link_libraries(uml001_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        ${SODIUM_LIBRARY}
)

# ------------------------------------------------------------
# Python extension module (pybind11)
# ------------------------------------------------------------
add_library(uml001 MODULE
    src/python/uml001_bindings.cpp
)

target_link_libraries(uml001
    PRIVATE
        pybind11::module
        uml001_core
        ${SODIUM_LIBRARY}
)

set_target_properties(uml001 PROPERTIES PREFIX "")

if (WIN32)
    set_target_properties(uml001 PROPERTIES SUFFIX ".pyd")
endif()

# ------------------------------------------------------------
# Installation
# ------------------------------------------------------------
install(TARGETS uml001_core uml001
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/ DESTINATION include)
