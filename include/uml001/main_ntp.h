#pragma once

// =============================================================================
//  main_shared_clock.h
//  UML-001 BFT Quorum Clock — Shared State Store Integration
//
//  Declares all types and free functions used by main_shared_clock.cpp:
//
//    SharedClockState       — POD snapshot promoted to Redis after each BFT sync
//    RedisSharedStore       — WATCH/MULTI transactional Redis adapter interface
//    background_sync_loop() — NTP fetch + BFT sync + Redis promotion loop
//
//  Design constraints:
//    • All timing goes through the BFT-verified IClock interface (clock.h).
//      std::chrono::system_clock is used ONLY for degradation window staleness
//      checks, where the question is "how long since Redis was last written" —
//      a liveness property that does not require cryptographic assurance.
//    • All shared-state writes use Redis WATCH/MULTI/EXEC for optimistic
//      concurrency.  A failed EXEC (another instance beat us) is not an error;
//      the winner's value is consumed by apply_shared_state() instead.
//    • The degradation window is a configurable value passed into
//      background_sync_loop().  It is NOT a compile-time constant.
//
//  Thread safety:
//    background_sync_loop() is designed to run in exactly one std::thread.
//    RedisSharedStore implementations must be thread-safe if the same instance
//    is shared between the sync thread and a health-check thread.
//
//  Dependencies (all headers must be available on the include path):
//    strong_clock.h          — IClock, SecurityViolation, validate_timestamp
//    bft_quorum_clock.h      — BFTQuorumTrustedClock, QuorumResult
//    ntp_observation_fetcher.h — NtpObservationFetcher
//    vault.h                 — ColdVault
//    crypto_utils.h          — generate_random_bytes_hex, register_hmac_authority
//
//  Platform:
//    POSIX and Windows — see ntp_observation_fetcher.h for socket portability.
//    No POSIX-specific APIs are used in this header or main_shared_clock.cpp.
//
//  Standards:
//    RFC 5905  §11   NTP poll interval constraints (60 s default respects limits)
//    NIST SP 800-92  Audit log requirements (degradation events logged to vault)
//    NIST SP 800-90A CSPRNG for HMAC key generation
//    CWE-362         Race condition prevention via atomic operations
//    CWE-190         Integer overflow prevention (uint64_t timestamp arithmetic)
// =============================================================================

#include "strong_clock.h"
#include "uml001/bft_quorum_clock.h"
#include "uml001/ntp_observation_fetcher.h"
#include "uml001/vault.h"
#include "uml001/crypto_utils.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>

// =============================================================================
// SharedClockState
// =============================================================================
//
// Plain data snapshot of the agreed BFT clock state, as stored in the shared
// Redis key.  All fields are value types; no pointers, no references.
//
// Fields
// ------
//   agreed_time          Consensus Unix timestamp (seconds) produced by the
//                        BFT cluster selection algorithm.  This is the value
//                        all instances read from Redis instead of running their
//                        own independent NTP fetch + quorum computation.
//
//   applied_drift        Signed cumulative drift offset (seconds) applied to
//                        the raw clock to produce agreed_time.  Included so
//                        that apply_shared_state() can reconstruct the BFT
//                        clock's internal drift accumulator, preserving the
//                        max_total_drift anti-creep ceiling across instances.
//
//   last_updated_unix    Wall-clock Unix timestamp (seconds) at which this
//                        record was written to Redis, taken from
//                        std::chrono::system_clock on the writing instance.
//                        Used only for degradation window staleness checks —
//                        not for any auth-bearing timestamp comparison.
//
// Serialisation
// -------------
// Implementations of RedisSharedStore are responsible for serialising and
// deserialising this struct to/from the Redis value.  A simple approach is
// JSON or a pipe-delimited string.  The recommended production format is a
// HMAC-signed JSON blob (see vault.h SignedVaultRecord for the signing model).
// =============================================================================
struct SharedClockState {
    uint64_t agreed_time;           ///< BFT-agreed Unix timestamp (seconds)
    int64_t  applied_drift;         ///< Signed cumulative drift offset (seconds)
    uint64_t last_updated_unix;     ///< Writer's wall-clock time (seconds, system_clock)
};


// =============================================================================
// RedisSharedStore
// =============================================================================
//
// Abstract interface for the shared clock state store.  The concrete
// implementation wraps a Redis client (e.g. hiredis, redis-plus-plus, or
// Jedis via JNI) and performs the WATCH/MULTI/EXEC transaction pattern for
// optimistic concurrency.
//
// The mock implementation in main_shared_clock.cpp fulfils this interface with
// an in-process std::optional<SharedClockState>.  Production code replaces it
// with a real Redis adapter while keeping the rest of main_shared_clock.cpp
// unchanged.
//
// Concurrency model
// -----------------
// A WATCH/MULTI/EXEC sequence on the clock state key is:
//
//   WATCH  clock_state_key
//   MULTI
//   SET    clock_state_key  <serialised SharedClockState>
//   EXEC
//
// EXEC returns nil if any watched key was modified between WATCH and EXEC,
// indicating another instance committed first.  watch_and_commit() returns
// false in that case.  The caller (background_sync_loop) treats false as a
// no-error condition and reads the winner's state on the next tick.
//
// read_state()
// ------------
// Returns the current shared state, or std::nullopt if the key does not yet
// exist (first-run, Redis restart, or explicit flush).  Must not throw.
//
// watch_and_commit()
// ------------------
// Attempts an atomic WATCH/MULTI/EXEC write of new_state.
//   Returns true  — the commit succeeded; this instance is the winner.
//   Returns false — the commit was aborted by a concurrent write from another
//                   instance; the caller should read the winner's state.
// May throw std::runtime_error on connection failure, serialisation error, or
// other non-recoverable Redis errors.
// =============================================================================
class RedisSharedStore {
public:
    virtual ~RedisSharedStore() = default;

    /// Read the current shared clock state from the store.
    /// Returns std::nullopt if no state has been written yet.
    /// Must not throw on missing key; may throw on connection failure.
    virtual std::optional<SharedClockState> read_state() = 0;

    /// Atomically write new_state using WATCH/MULTI/EXEC.
    /// Returns true if the commit succeeded; false if aborted by a concurrent
    /// write from another instance.
    /// May throw std::runtime_error on connection failure.
    virtual bool watch_and_commit(const SharedClockState& new_state) = 0;
};


// =============================================================================
// RedisSharedStoreMock
// =============================================================================
//
// In-process mock implementation of RedisSharedStore.  Stores state in a plain
// std::optional<SharedClockState>.  Suitable for unit tests and single-instance
// development runs.  Thread safety: not guaranteed — add a mutex if the mock is
// accessed from multiple threads simultaneously.
// =============================================================================
class RedisSharedStoreMock final : public RedisSharedStore {
public:
    std::optional<SharedClockState> read_state() override;
    bool watch_and_commit(const SharedClockState& new_state) override;

private:
    std::optional<SharedClockState> cached_state_;
};


// =============================================================================
// background_sync_loop()
// =============================================================================
//
// Long-running synchronisation loop intended to execute in a dedicated
// std::thread.  Each iteration performs:
//
//  1. Degradation window check
//     Reads the shared state's last_updated_unix and compares it to the
//     current system wall clock.  If the gap exceeds degradation_window_s,
//     a warning is written to stderr AND a degradation event is appended to
//     the vault audit log (NIST SP 800-92 compliance).
//
//  2. Sync interval gating
//     Ticks at 500 ms intervals internally.  An NTP fetch is only triggered
//     every interval_s seconds.  This respects RFC 5905 §7.2 minimum poll
//     intervals and NIST time.nist.gov's ≤1 query per 4 s per server request.
//
//  3. Early-exit if Redis state is fresh
//     If another instance updated Redis within interval_s / 2 seconds, this
//     instance skips the NTP fetch and calls clock.apply_shared_state() to
//     synchronise its local BFT clock to the shared consensus.  This prevents
//     all N instances in a fleet from querying public NTP servers
//     simultaneously.
//
//  4. NTP fetch + BFT sync
//     If this instance is the active worker (Redis state is stale or absent),
//     it calls fetcher.fetch(), then clock.update_and_sync().  On success, the
//     QuorumResult is packaged into a SharedClockState and committed to Redis
//     via watch_and_commit().
//
//  5. Sequence persistence
//     After a successful Redis commit, per-server NTP sequence counters are
//     persisted to the vault so that cross-restart replay protection is tight.
//
// Parameters
// ----------
//   clock               BFTQuorumTrustedClock instance owned by the caller.
//                       apply_shared_state() must be callable on this object
//                       to synchronise a non-fetching instance to the shared
//                       consensus without re-running the BFT algorithm.
//
//   fetcher             NtpObservationFetcher.  Queries the configured NTP
//                       server pool.  Must be pre-initialised with sequence
//                       state loaded from the vault.
//
//   vault               ColdVault for sequence persistence and degradation
//                       event audit logging.  Shared with the BFT clock.
//
//   redis_store         Concrete RedisSharedStore implementation.  May be the
//                       mock (single instance / tests) or a production Redis
//                       adapter.
//
//   interval_s          Seconds between NTP fetch cycles.  Minimum 16 s (RFC
//                       5905 §7.2); recommended 60 s for public NTP.
//
//   degradation_window_s
//                       Seconds after which a stale shared state triggers a
//                       degradation warning and vault audit entry.  Configurable
//                       per deployment; suggested default 120 s.
//
//   shutdown            Atomic flag.  Set to true to request clean shutdown.
//                       The loop exits at the next 500 ms tick boundary.
//
// Exception behaviour
// -------------------
// std::exception thrown by fetcher.fetch(), clock.update_and_sync(), or
// redis_store.watch_and_commit() are caught, logged to stderr, and the loop
// continues.  The loop does not rethrow.  A persistent exception (e.g. network
// outage) will cause repeated catch-and-continue until the degradation window
// fires and the application's fail-safe handler takes over.
// =============================================================================
void background_sync_loop(
    uml001::BFTQuorumTrustedClock&  clock,
    uml001::NtpObservationFetcher&  fetcher,
    ColdVault&                      vault,
    RedisSharedStore&               redis_store,
    uint64_t                        interval_s,
    uint64_t                        degradation_window_s,
    std::atomic<bool>&              shutdown
);