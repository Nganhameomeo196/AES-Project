# Technical scope and experiment integrity

- AES-128/192/256 from scratch: state, S-box, inverse, round keys, encrypt and decrypt.
- ECB/CBC/CTR/GCM educational implementations; test known vectors and tamper handling.
- Round trace uses the same primitives as the block cipher and is tested against its output.
- Toy differential distribution and linear approximation tables illustrate concepts on a 4-bit substitution only.
- Synthetic side-channel CSV simulates a Hamming-weight power signal and cache bucket; no actual leakage is measured.
- ECB/tampering/brute-force demonstrations illustrate risks, not cryptanalysis of full AES.
- Related-key and biclique are not claimed as implemented attacks against AES; fault/caching/physical power require a carefully scoped lab and hardware or instrumented implementations.
- Benchmark includes warm-up, batched samples, median, mean, standard deviation, platform metadata. Results are not universal performance claims.
- No software can guarantee a grade. Re-run tests and experiments on the submission machine.
