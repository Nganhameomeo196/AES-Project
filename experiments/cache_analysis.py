"""Recover a synthetic S-box key byte from exact 16-entry cache-bucket labels.

This assumes an unrealistic perfect observation of cache buckets, not a real attack.
"""
import csv
from pathlib import Path
from src.key_expansion import SBOX


def run(input_file='results/synthetic_sidechannel.csv', output='results/cache_candidates.csv'):
    with Path(input_file).open(newline='') as handle:
        samples = list(csv.DictReader(handle))
    rows = []
    for count in (1, 2, 4, 8, 16, 32, 64, len(samples)):
        subset = samples[:min(count, len(samples))]
        candidates = [key for key in range(256) if all(
            SBOX[int(row['plaintext_byte']) ^ key] // 16 == int(row['synthetic_cache_bucket'])
            for row in subset)]
        rows.append({'samples': len(subset), 'candidate_count': len(candidates),
                     'candidate_hex': ' '.join(f'{key:02x}' for key in candidates)})
    path = Path(output)
    with path.open('w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print('Synthetic cache candidate counts:', [(r['samples'], r['candidate_count']) for r in rows])
    return rows


if __name__ == '__main__':
    run()
