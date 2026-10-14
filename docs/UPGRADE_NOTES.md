# Implementation upgrade notes

- Importing `src.demo_ui` no longer creates a window. Use `python -m src.demo_ui`.
- GCM encryption in the GUI generates a fresh random 12-byte nonce and displays it for decryption. Never reuse a nonce with the same key.
- GUI supports Block, ECB, CBC, CTR and GCM; round-by-round tracing is supported for Block mode.
- Key schedules are cached internally as immutable tuples, but the public `round_keys` API still returns independent lists so callers cannot corrupt the cache.
- ECB and CBC APIs apply PKCS#7 padding. NIST SP 800-38A block vectors are checked against the first ciphertext block, while decryption round-trips the padded ciphertext.
- NIST GCM AAD/multiblock test covers authentication and AAD tampering.
- `experiments/ecb_image.py` outputs uncompressed PPM files; image data is synthetic.
- `experiments/sidechannel_sim.py` performs Pearson-correlation CPA on simulated power samples. This is **not** real-world key extraction.
- `experiments/toy_cryptanalysis.py` includes the original toy 4-bit S-box plus full 8-bit AES S-box DDT and LAT using a Walsh-Hadamard transform. Nonzero differential maximum = 4; maximum linear bias = 16 out of 256.
- Timing/cache/fault/related-key/biclique experiments are not yet comprehensive implementations. Do not present simulated results as hardware measurements or full AES attacks.
- Pure-Python cryptography is not guaranteed constant-time; for production security use a reviewed cryptographic library.
