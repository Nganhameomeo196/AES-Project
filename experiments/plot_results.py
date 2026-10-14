"""Generate reproducible charts from existing CSV files (matplotlib optional)."""
import csv
from pathlib import Path


def read_csv(path):
    path=Path(path)
    if not path.exists():
        print(f'Skipping {path}: file not found')
        return []
    with path.open(encoding='utf8',newline='') as file:
        return list(csv.DictReader(file))


def run(output='results'):
    try:
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise SystemExit('Install matplotlib: python -m pip install matplotlib') from exc
    folder=Path(output)
    folder.mkdir(parents=True,exist_ok=True)
    rows=read_csv(folder/'benchmark.csv')
    for operation in ('encrypt','decrypt','key_expansion'):
        subset=[r for r in rows if r['operation']==operation]
        if not subset:continue
        fig,ax=plt.subplots(figsize=(7,4))
        ax.bar([r['algorithm'] for r in subset],[float(r['median_us']) for r in subset])
        ax.set(ylabel='Median time (microseconds)',title=f'AES {operation} (Python)')
        fig.tight_layout();fig.savefig(folder/f'{operation}_chart.png',dpi=160);plt.close(fig)
    rows=read_csv(folder/'avalanche.csv')
    if rows:
        fig,ax=plt.subplots(figsize=(8,4))
        for size in (128,192,256):
            subset=[r for r in rows if int(r['aes_bits'])==size and r['changed']=='plaintext']
            ax.plot([int(r['round']) for r in subset],[float(r['mean_changed_bits']) for r in subset],marker='o',label=f'AES-{size}')
        ax.set(xlabel='Round',ylabel='Changed bits (of 128)',title='Avalanche effect')
        ax.legend();fig.tight_layout();fig.savefig(folder/'avalanche_chart.png',dpi=160);plt.close(fig)
    rows=read_csv(folder/'cpa_correlations.csv')
    if rows:
        fig,ax=plt.subplots(figsize=(10,4))
        ax.bar([int(r['candidate']) for r in rows],[float(r['correlation']) for r in rows],width=1)
        ax.set(xlabel='Key-byte hypothesis',ylabel='Pearson correlation',title='Synthetic CPA (not physical leakage)')
        fig.tight_layout();fig.savefig(folder/'cpa_chart.png',dpi=160);plt.close(fig)
    rows=read_csv(folder/'cpa_success.csv')
    if rows:
        fig, ax = plt.subplots(figsize=(8, 4))
        for noise in sorted({float(r['noise_sigma']) for r in rows}):
            subset = [r for r in rows if float(r['noise_sigma']) == noise]
            ax.plot([int(r['samples']) for r in subset],
                    [float(r['success_rate']) for r in subset], marker='o', label=f'Noise {noise}')
        ax.set(xlabel='Synthetic traces', ylabel='CPA success rate',
               title='Synthetic CPA recovery vs. noise', ylim=(0, 1.05))
        ax.legend()
        fig.tight_layout()
        fig.savefig(folder/'cpa_success_chart.png', dpi=160)
        plt.close(fig)
    rows=read_csv(folder/'mode_benchmark.csv')
    if rows:
        fig,ax=plt.subplots(figsize=(8,4))
        for mode in ('ECB','CBC','CTR','GCM'):
            subset=[r for r in rows if r['mode']==mode]
            ax.plot([int(r['bytes'])/1024 for r in subset],[float(r['throughput_kib_s']) for r in subset],marker='o',label=mode)
        ax.set(xlabel='Input size (KiB)',ylabel='Throughput (KiB/s)',title='Pure-Python AES mode throughput')
        ax.legend();fig.tight_layout();fig.savefig(folder/'modes_chart.png',dpi=160);plt.close(fig)
    for name in ('aes_sbox_ddt','aes_sbox_lat'):
        path=folder/f'{name}.csv'
        if not path.exists():continue
        with path.open(newline='') as file:
            reader=csv.reader(file);next(reader)
            matrix=[[int(v) for v in row[1:]] for row in reader]
        fig,ax=plt.subplots(figsize=(7,6))
        ax.imshow(matrix,aspect='auto',interpolation='nearest',cmap='viridis')
        ax.set(xlabel='Output mask/difference',ylabel='Input mask/difference',title=name)
        fig.tight_layout();fig.savefig(folder/f'{name}.png',dpi=150);plt.close(fig)
    print('Charts generated in',folder)

if __name__=='__main__':run()
