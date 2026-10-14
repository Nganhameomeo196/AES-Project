# Review fixes (2026-10-14)

- MixColumns uses precomputed GF(2^8) tables; the public block API and AES algorithms remain unchanged.
- NIST SP 800-38A ECB/CBC/CTR vectors now cover four consecutive blocks for AES-128/192/256, including CBC chaining and CTR counter increments.
- Benchmark's `__main__` runs block and mode measurements. Its **quick default** tests 1 KiB and 4 KiB, since pure Python is slow. Run `benchmark_modes(sizes=(1024,65536,1048576), repeats=2)` manually for larger sizes (may take several minutes).
- Avalanche CSV was regenerated using the default 500 trials (78 rows).
- Mode benchmark CSV and charts were regenerated from the actual implementation.
- GUI supports Hex and UTF-8 input, with 16-byte IV refresh for CBC/CTR encryption and fresh 12-byte GCM nonce.
- ECB image demo exports both PPM and PNG. The generated picture is a synthetic checkerboard, not a real logo.
- Added educational fault propagation at round 9, perfect-information synthetic cache-bucket candidate filtering, and synthetic CPA success rate by trace count/noise.
- The cache, CPA and fault experiments are **simulations**, not successful attacks on real AES implementations or devices.
- Existing semicolon-heavy modules have not yet undergone a comprehensive style refactor; this is intentionally deferred to avoid changing working cryptographic logic.
- Related-key, biclique, real hardware timing/power/cache attacks and a practical DFA key-recovery procedure remain out of scope for the executable demos.
