"""Avalanche experiment: deterministic sampling, no external dependencies."""
import csv,random,statistics
from pathlib import Path
from src.trace import encrypt_trace

def distance(a,b):return sum((x^y).bit_count() for x,y in zip(a,b))

def run(trials=500,seed=2026,output="results/avalanche.csv"):
    rng=random.Random(seed);rows=[]
    for key_size in (16,24,32):
        for changed in ("plaintext","key"):
            samples={}
            for trial in range(trials):
                pt=bytes(rng.getrandbits(8) for _ in range(16))
                key=bytes(rng.getrandbits(8) for _ in range(key_size))
                altered=bytearray(pt if changed=="plaintext" else key)
                pos=rng.randrange(len(altered)*8);altered[pos//8]^=1<<(pos%8)
                other_pt=bytes(altered) if changed=="plaintext" else pt
                other_key=bytes(altered) if changed=="key" else key
                baseline={e["round"]:bytes.fromhex(e["state"]) for e in encrypt_trace(pt,key) if e["step"]=="AddRoundKey"}
                modified={e["round"]:bytes.fromhex(e["state"]) for e in encrypt_trace(other_pt,other_key) if e["step"]=="AddRoundKey"}
                for r in baseline:samples.setdefault(r,[]).append(distance(baseline[r],modified[r]))
            for r,vals in sorted(samples.items()):rows.append({"aes_bits":key_size*8,"changed":changed,"round":r,"mean_changed_bits":round(sum(vals)/len(vals),3),"stdev_changed_bits":round(statistics.stdev(vals),3) if len(vals)>1 else 0,"trials":trials,"seed":seed})
    dest=Path(output);dest.parent.mkdir(parents=True,exist_ok=True)
    with dest.open("w",newline="",encoding="utf8") as f:
        writer=csv.DictWriter(f,fieldnames=rows[0].keys());writer.writeheader();writer.writerows(rows)
    print("Saved",dest,"rows:",len(rows))
    return rows

if __name__=="__main__":run()
