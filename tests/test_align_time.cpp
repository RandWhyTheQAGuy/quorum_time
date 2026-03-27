#include <iostream>
#include <cassert>
#include <vector>
#include "uml001/align_time.h"
#include "uml001/crypto_interfaces.h"

using namespace uml001;

// A minimal Mock provider for testing the loop
class MockSignProvider : public ISignProvider {
public:
    std::vector<uint8_t> sign(const std::vector<uint8_t>& data) override {
        // Return a dummy signature (e.g., hash of data for simplicity in test)
        return {0xDE, 0xAD, 0xBE, 0xEF}; 
    }
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sig) override {
        // Mock verification: check if sig matches our dummy signature
        return sig == std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF};
    }
};

void test_alignment_signature_loop() {
    MockSignProvider mock_signer;
    // Assuming simple_hash_provider is already implemented in src/core/
    // If not, a minimal mock for IHashProvider would go here.
    // For this logic test, we focus on the SignProvider.
    
    // We don't actually call hasher in the current AlignTimeManager impl, 
    // but it's in the constructor for future ZK expansion.
    AlignTimeManager manager(mock_signer, /* hash_provider_placeholder */);

    AlignmentPoint point;
    point.peer_id = "peer-alpha-001";
    point.session_id = "session-uuid-999";
    point.timestamp = 1711540000;
    point.local_anchor = {0x01, 0x02, 0x03};
    point.remote_anchor = {0x04, 0x05, 0x06};

    // 1. Sign local
    manager.sign_local(point);
    assert(!point.signature.empty());
    std::cout << "[PASS] Local signing complete." << std::endl;

    // 2. Verify remote (using same dummy "public key" for mock)
    bool is_valid = manager.verify_remote(point, {0xAA, 0xBB});
    assert(is_valid == true);
    std::cout << "[PASS] Handshake verification successful." << std::endl;

    // 3. Tamper test: Modify timestamp
    point.timestamp += 1;
    bool is_valid_tampered = manager.verify_remote(point, {0xAA, 0xBB});
    assert(is_valid_tampered == false);
    std::cout << "[PASS] Tamper detection (Timestamp) verified." << std::endl;
}

int main() {
    try {
        test_alignment_signature_loop();
        std::cout << "\nALL ALIGN_TIME CORE TESTS PASSED" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test failed: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}