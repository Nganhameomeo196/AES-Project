"""Synthetic leakage/fault illustrations. No physical device measurements."""
import csv,random,math
from pathlib import Path
from src.key_expansion import SBOX

def run(samples=256,seed=2026):
    rng=random.Random(seed);secret=rng.randrange(256)
    rows=[]
    for i in range(samples):
        pt=rng.randrange(256)
        intermediate=SBOX[pt^secret]
        power=intermediate.bit_count()+rng.gauss(0,0.7)
        cache_bucket=intermediate//16
        rows.append({"sample":i,"plaintext_byte":pt,"synthetic_power":round(power,4),"synthetic_cache_bucket":cache_bucket})
    out=Path("results/synthetic_sidechannel.csv");out.parent.mkdir(exist_ok=True)
    with out.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
    def corr(a,b):
        ma=sum(a)/len(a); mb=sum(b)/len(b)
        numerator=sum((x-ma)*(y-mb) for x,y in zip(a,b))
        denominator=math.sqrt(sum((x-ma)**2 for x in a)*sum((y-mb)**2 for y in b))
        return numerator/denominator if denominator else 0.0
    measured=[r["synthetic_power"] for r in rows]
    guesses=[]
    for candidate in range(256):
        predicted=[SBOX[r["plaintext_byte"]^candidate].bit_count() for r in rows]
        guesses.append({"candidate":candidate,"correlation":corr(predicted,measured)})
    recovered=max(guesses,key=lambda x:abs(x["correlation"]))["candidate"]
    with Path("results/cpa_correlations.csv").open("w",newline="") as file:
        writer=csv.DictWriter(file,fieldnames=["candidate","correlation"])
        writer.writeheader();writer.writerows(guesses)
    print(f"Synthetic CPA: true key byte={secret:02x}, recovered={recovered:02x}; success={secret==recovered}")
    print("Saved",out,"synthetic measurements; no real hardware used")
    return rows
if __name__=="__main__":run()
