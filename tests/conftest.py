import pytest
import subprocess
import time
import socket
import os

def wait_for_server(host="127.0.0.1", port=50051, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.5)
    return False

@pytest.fixture(scope="session", autouse=True)
def run_test_server():
    # 1. Clean up old test data before starting
    test_data_dir = "./test_data"
    if not os.path.exists(test_data_dir):
        os.makedirs(test_data_dir)
    
    env = os.environ.copy()
    env["AEGIS_DATA_DIR"] = test_data_dir

    # 2. Start the process
    proc = subprocess.Popen(
        ["./build/aegis_clock_server", "--data-dir", test_data_dir, "--insecure-dev"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env
    )

    # 3. Wait with a slightly longer timeout for macOS
    if not wait_for_server(timeout=10):
        # Capture logs to see why it failed
        stdout, stderr = proc.communicate(timeout=1)
        proc.terminate()
        raise RuntimeError(f"Server failed to start.\nSTDOUT: {stdout}\nSTDERR: {stderr}")

    yield proc

    # 4. Shutdown
    proc.terminate()
    proc.wait()