"""Synthetic CPA success rate by sample count and Gaussian noise level."""
import csv
import math
import random
from pathlib import Path
from src.key_expansion import SBOX


def correlation(xs, ys):
    mx = sum(xs) / len(xs)
    my = sum(ys) / len(ys)
    numerator = sum((x-mx)*(y-my) for x, y in zip(xs, ys))
    denominator = math.sqrt(sum((x-mx)**2 for x in xs) * sum((y-my)**2 for y in ys))
    return numerator / denominator if denominator else 0.0


def run(trials=12, sizes=(16, 32, 64, 128), noises=(0.5, 1.5, 3.0), seed=2026,
        output='results/cpa_success.csv'):
    rng = random.Random(seed)
    rows = []
    for noise in noises:
        for samples in sizes:
            successes = 0
            for _ in range(trials):
                key = rng.randrange(256)
                plaintext = [rng.randrange(256) for _ in range(samples)]
                leakage = [SBOX[x ^ key].bit_count() + rng.gauss(0, noise) for x in plaintext]
                scores = [abs(correlation([SBOX[x ^ candidate].bit_count() for x in plaintext], leakage))
                          for candidate in range(256)]
                successes += max(range(256), key=lambda k: scores[k]) == key
            rows.append({'noise_sigma': noise, 'samples': samples, 'trials': trials,
                         'successes': successes, 'success_rate': round(successes / trials, 4)})
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print('Saved', path)
    return rows


if __name__ == '__main__':
    run()
