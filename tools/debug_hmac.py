import hmac
import hashlib
import time
import requests
from sdks.python.uml001.crypto_utils import hmac_sha256_hex

# Configuration matching your server start command
SERVER_URL = "http://localhost:8080"
KEY_ID = "v1"
SECRET_HEX = "0123456789abcdef0123456789abcdef" # Example 32-byte secret

def test_signed_observation():
    """
    Manually signs an observation and sends it to the server.
    """
    host = "pool.ntp.org"
    timestamp = int(time.time())
    sequence = 1
    
    # Construct the payload string as the server expects (hostname:timestamp:seq)
    payload = f"{host}:{timestamp}:{sequence}"
    
    # Generate the signature using your utility
    sig = hmac_sha256_hex(payload, SECRET_HEX)
    
    print(f"--- Debugging HMAC ---")
    print(f"Payload:   {payload}")
    print(f"Signature: {sig}")
    
    # Send to the server
    obs_data = {
        "observations": [{
            "server_hostname": host,
            "key_id": KEY_ID,
            "unix_seconds": timestamp,
            "signature_hex": sig,
            "sequence": sequence
        }],
        "warp_score": 0.0
    }
    
    try:
        r = requests.post(f"{SERVER_URL}/time/sync", json=obs_data, headers={"X-API-Key": "supersecret"})
        print(f"Status:    {r.status_code}")
        print(f"Response:  {r.json()}")
    except Exception as e:
        print(f"Error:     {e}")

if __name__ == "__main__":
    test_signed_observation()