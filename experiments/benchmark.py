"""Warm-up + repeated batch timings for AES and key schedule."""
import csv,statistics,time,platform,sys
from pathlib import Path
from src.aes_encrypt import aes_encrypt
from src.aes_decrypt import aes_decrypt
from src.key_expansion import round_keys

def run(iterations=30,batches=5,warmup=5):
    if min(iterations,batches,warmup)<1:raise ValueError("All measurement counts must be positive")
    rows=[];block=bytes(range(16))
    for size in (16,24,32):
        key=bytes(range(size));ct=aes_encrypt(block,key)
        for name,fn in (("key_expansion",lambda:round_keys(key)),("encrypt",lambda:aes_encrypt(block,key)),("decrypt",lambda:aes_decrypt(ct,key))):
            for _ in range(warmup):fn()
            measurements=[]
            for _ in range(batches):
                start=time.perf_counter_ns()
                for _ in range(iterations):fn()
                measurements.append((time.perf_counter_ns()-start)/iterations/1000)
            rows.append({"algorithm":f"AES-{size*8}","operation":name,"median_us":round(statistics.median(measurements),3),"mean_us":round(statistics.mean(measurements),3),"stdev_us":round(statistics.stdev(measurements),3) if len(measurements)>1 else 0,"iterations_per_batch":iterations,"batches":batches,"warmup":warmup,"python":platform.python_version(),"platform":platform.platform()})
    out=Path("results/benchmark.csv");out.parent.mkdir(exist_ok=True)
    with out.open("w",newline="",encoding="utf8") as f:
        w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
    for row in rows:print(row)
    return rows



def benchmark_modes(sizes=(1024, 4096), repeats=2, include_1mb=False):
    """Measure throughput for all modes; GCM uses pure-Python GHASH."""
    from src.modes import ecb_encrypt, cbc_encrypt, ctr_crypt, gcm_encrypt
    if include_1mb:
        sizes=tuple(sizes)+(1024*1024,)
    key=bytes(range(16));iv=bytes(16);nonce=bytes(range(12))
    rows=[]
    for size in sizes:
        data=bytes((i*73)%256 for i in range(size))
        for name,fn in [('ECB',lambda:ecb_encrypt(data,key)),('CBC',lambda:cbc_encrypt(data,key,iv)),
                        ('CTR',lambda:ctr_crypt(data,key,iv)),('GCM',lambda:gcm_encrypt(data,key,nonce))]:
            times=[]
            for _ in range(repeats):
                start=time.perf_counter();fn();times.append(time.perf_counter()-start)
            median=statistics.median(times)
            rows.append({'mode':name,'bytes':size,'median_seconds':round(median,6),
                         'throughput_kib_s':round(size/1024/median,3),'min_seconds':round(min(times),6),
                         'max_seconds':round(max(times),6),'repeats':repeats})
    path=Path('results/mode_benchmark.csv');path.parent.mkdir(exist_ok=True)
    with path.open('w',newline='') as file:
        writer=csv.DictWriter(file,fieldnames=rows[0]);writer.writeheader();writer.writerows(rows)
    print('Saved',path)
    return rows


if __name__ == "__main__":
    run()
    benchmark_modes()
