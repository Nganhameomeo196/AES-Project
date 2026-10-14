# AES Project — Python educational implementation

**Academic demonstration, NOT production-grade encryption.** Original group AES code is retained and extended with modes, traces, experiments, CLI, and tests. ECB is insecure for repeated blocks; CBC/CTR need careful IV management; GCM nonces must never repeat for a given key. Use an audited library for real security.

## Requirements
- Python 3.10+ (recommended 3.11+)
- Standard library only for AES, tests, CLI, experiments and Tkinter GUI (Tkinter installation varies by OS)
- Optional for charts: `python -m pip install matplotlib`

## Run from repository root
```powershell
python -m unittest discover -s tests -v
python -m src.main
python -m src.demo_ui
python -m experiments.benchmark
python -m experiments.avalanche
python -m experiments.toy_cryptanalysis
python -m experiments.sidechannel_sim
python -m experiments.attack_demos
python -m experiments.plot_results
```

## CLI examples
```powershell
python -m src.cli encrypt --mode block --key 000102030405060708090a0b0c0d0e0f --data 00112233445566778899aabbccddeeff
python -m src.cli trace --mode block --key 000102030405060708090a0b0c0d0e0f --data 00112233445566778899aabbccddeeff
```

## Layout
- `src/`: AES, key schedule, modes, trace, CLI and GUI
- `tests/`: FIPS vectors, roundtrips, tamper rejection and edge cases
- `experiments/`: benchmarks, avalanche, toy differential/linear analysis, synthetic side-channel, mode demos
- `results/`: generated CSV and plots
- `docs/`: implementation notes and educational scope

## Limits
- AES block operations accept exactly 16-byte inputs.
- ECB and CBC use PKCS#7 padding; CTR and GCM handle arbitrary-length byte strings.
- GCM tag is 16 bytes; verify before releasing plaintext.
- Differential/linear toy tables and synthetic leakage **do not break full AES**.
- Benchmark measurements vary by CPU, Python and environment; rerun locally.
- Attack names (related-key, biclique, cache, power, fault) require separate scoped research/measurement; do not present toy simulations as real exploits.

## October upgrade: tests, GUI and experiments

The AES implementation and ECB/CBC/CTR/GCM are **educational Python implementations** and should not be used for real-world security. The GUI generates a new 96-bit GCM nonce for each encryption. For CBC/CTR, an IV/initial counter is generated when the field is empty; preserve it alongside the ciphertext for decryption and never reuse a CTR initial counter with the same key.

```bash
python -m unittest discover -s tests -v
python -m src.demo_ui
python -m src.cli --help
python -m experiments.ecb_image
python -m experiments.sidechannel_sim
python -m experiments.toy_cryptanalysis
python -m experiments.avalanche
python -m experiments.plot_results
```

`experiments.ecb_image` outputs `.ppm` image files; most image viewers support PPM, or convert them to PNG externally. Synthetic CPA guesses the key byte from an **artificial Hamming-weight leakage model**, not a real device. AES S-box DDT/LAT are mathematical properties of the S-box, not practical attacks on AES. The unit tests include NIST SP 800-38A mode vectors and a GCM AAD/multiblock vector. Benchmark mode throughput can be generated with:

```bash
python -c "from experiments.benchmark import benchmark_modes; benchmark_modes()"
```

To include 1 MiB (can be slow in pure Python):

```bash
python -c "from experiments.benchmark import benchmark_modes; benchmark_modes(include_1mb=True)"
```

GitHub Actions automatically runs the standard-library `unittest` suite on push and pull requests. Optional charting requires `python -m pip install matplotlib`.
