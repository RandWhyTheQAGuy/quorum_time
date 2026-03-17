import sys
import os

# Project root = one directory above tests/
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Expected build output directory (CMake default)
# Adjust if your build directory differs.
BUILD_DIR = os.path.join(ROOT, "build", "Release")

# Add the build directory to sys.path so Python can import `uml001`
if os.path.isdir(BUILD_DIR):
    sys.path.insert(0, BUILD_DIR)
else:
    print(f"[conftest] Warning: build directory not found: {BUILD_DIR}")
