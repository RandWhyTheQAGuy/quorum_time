#!/usr/bin/env bash
# build_and_test.sh
set -e

# Get absolute path to the project root
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

echo "🧹 [1/4] Cleaning previous builds..."
rm -rf build
find sdks/python/uml001 -name "_uml001*.so" -delete
find sdks/python/uml001 -name "_uml001*.dylib" -delete

echo "🏗️ [2/4] Compiling Core & Python Bindings..."
mkdir build && cd build
cmake ..
# Use all available cores for a faster build
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

echo "📦 [3/4] Installing binary to Python SDK..."
# Copy the compiled module into the package directory
cp _uml001* "$ROOT/sdks/python/uml001/"

echo "🧪 [4/4] Running Tests..."
export PYTHONPATH="$ROOT/sdks/python"
cd "$ROOT"

# Test a simple import first to catch linking errors early
python3 -c "import uml001; print('✅ SDK Link Successful')"

# Run the key rotation test specifically, then the rest
pytest -v tests/test_key_rotation.py
pytest -v tests --ignore=tests/test_rest_api.py

echo "🚀 Build and Test cycle complete."

echo "🚀 [4/4] Finalizing Python Package..."
# Find the compiled library (handles different python versions/platforms)
BINARY_PATH=$(find build -name "_uml001*.so" -o -name "_uml001*.pyd" | head -n 1)

if [ -f "$BINARY_PATH" ]; then
    cp "$BINARY_PATH" sdks/python/uml001/
    echo "✅ Extension copied to sdks/python/uml001/"
else
    echo "❌ Error: Could not find compiled extension in build directory."
    exit 1
fi

echo "✨ Build Complete. To run tests, remember to set PYTHONPATH:"
echo "   export PYTHONPATH=\$PYTHONPATH:\$(pwd)/sdks/python"