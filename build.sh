#!/usr/bin/env bash
set -e

# Move to project root
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Create build directory if missing
mkdir -p build
cd build

# Configure CMake
cmake ..

# Build everything (core library + pybind11 module)
cmake --build . --config Release

# Return to project root
cd "$ROOT_DIR"

# Run pytest with PYTHONPATH pointing to the compiled module
export PYTHONPATH="$ROOT_DIR/build/Release:$PYTHONPATH"
pytest -vv
