"""Differential/linear bias in a 4-bit toy substitution, NOT a real AES attack."""
import csv
from pathlib import Path
S=(0xC,5,6,0xB,9,0,0xA,0xD,3,0xE,0xF,8,4,7,1,2)

def parity(x):return x.bit_count()%2

def differential_table():
    return [[sum((S[x]^S[x^a])==b for x in range(16)) for b in range(16)] for a in range(16)]

def linear_table():
    return [[sum(1 if parity(x&a)==parity(S[x]&b) else -1 for x in range(16)) for b in range(16)] for a in range(16)]

def run():
    out=Path("results");out.mkdir(exist_ok=True)
    for name,table in (("toy_ddt",differential_table()),("toy_lat",linear_table())):
        with (out/(name+".csv")).open("w",newline="") as f:
            w=csv.writer(f);w.writerow(["input_mask"]+list(range(16)))
            for i,row in enumerate(table):w.writerow([i]+row)
    print("Toy cipher DDT and LAT saved (not cryptanalysis of full AES).")


def aes_sbox_tables(output_dir="results"):
    """AES 8-bit S-box DDT and Walsh LAT, not an attack on full AES."""
    from src.key_expansion import SBOX
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    ddt = [[0]*256 for _ in range(256)]
    lat = [[0]*256 for _ in range(256)]
    for delta in range(256):
        for x in range(256):
            ddt[delta][SBOX[x]^SBOX[x^delta]] += 1
    # Fast Walsh-Hadamard transform for each output mask (256 * 256 * 8).
    for b in range(256):
        transform=[1 if parity(SBOX[x]&b)==0 else -1 for x in range(256)]
        step=1
        while step<256:
            for start in range(0,256,2*step):
                for j in range(start,start+step):
                    u,v=transform[j],transform[j+step]
                    transform[j],transform[j+step]=u+v,u-v
            step*=2
        for a,value in enumerate(transform):lat[a][b]=value
    for name, matrix in (("aes_sbox_ddt",ddt),("aes_sbox_lat",lat)):
        with (out/(name+".csv")).open("w",newline="") as file:
            writer=csv.writer(file)
            writer.writerow(["mask"]+list(range(256)))
            for i,row in enumerate(matrix):writer.writerow([i]+row)
    max_ddt=max(max(row) for row in ddt[1:])
    max_bias=max(abs(lat[a][b])//2 for a in range(1,256) for b in range(1,256))
    print("AES S-box max nonzero differential count:",max_ddt,"; max LAT bias:",max_bias)
    return max_ddt,max_bias

if __name__ == "__main__":
    run()
    aes_sbox_tables()
