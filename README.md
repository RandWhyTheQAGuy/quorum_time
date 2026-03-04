Where "just trust NTP" is unacceptable, this framework ensures that everything else - tokens, sessions, revocation, audit, consensus - stand on solid temporal ground.

Quorum Clock is a defense-in-depth time authority system, which implements the following protections:

Authenticated, authorized, and replay-protected inputs.
BFT-style aggregation and outlier rejection.
Monotonic, drift-bounded output.
Fail-closed behavior on extreme anomalies.
Full audit trail of adjustments.
Config validation to avoid accidental weakening.