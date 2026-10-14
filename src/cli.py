"""Reproducible CLI: python -m src.cli --help"""
import argparse, json
from .aes_encrypt import aes_encrypt
from .aes_decrypt import aes_decrypt
from .modes import ecb_encrypt,ecb_decrypt,cbc_encrypt,cbc_decrypt,ctr_crypt,gcm_encrypt,gcm_decrypt
from .trace import encrypt_trace,decrypt_trace

def main():
    parser=argparse.ArgumentParser(description="AES educational CLI (hex input/output; not production crypto)")
    parser.add_argument("action",choices=["encrypt","decrypt","trace"])
    parser.add_argument("--mode",choices=["block","ecb","cbc","ctr","gcm"],default="block")
    parser.add_argument("--key",required=True,help="hex-encoded 16/24/32-byte key")
    parser.add_argument("--data",required=True,help="hex-encoded input")
    parser.add_argument("--iv",default=None,help="hex-encoded IV/nonce, required for CBC/CTR/GCM")
    parser.add_argument("--aad",default="",help="hex-encoded GCM additional authenticated data")
    parser.add_argument("--tag",default=None,help="hex-encoded GCM tag for decryption")
    args=parser.parse_args()
    try:
        key=bytes.fromhex(args.key);data=bytes.fromhex(args.data)
        if len(key) not in (16,24,32):raise ValueError("Key must contain 16/24/32 bytes")
        iv=bytes.fromhex(args.iv) if args.iv is not None else None
        aad=bytes.fromhex(args.aad)
        if args.action=="trace":
            if args.mode!="block":raise ValueError("Tracing supports block mode only")
            events=encrypt_trace(data,key)
            print(json.dumps(events,indent=2));return
        if args.mode in ("cbc","ctr","gcm") and iv is None:raise ValueError("--iv required")
        if args.mode=="block":out=aes_encrypt(data,key) if args.action=="encrypt" else aes_decrypt(data,key)
        elif args.mode=="ecb":out=ecb_encrypt(data,key) if args.action=="encrypt" else ecb_decrypt(data,key)
        elif args.mode=="cbc":out=cbc_encrypt(data,key,iv) if args.action=="encrypt" else cbc_decrypt(data,key,iv)
        elif args.mode=="ctr":out=ctr_crypt(data,key,iv)
        else:
            if args.action=="encrypt":
                out,tag=gcm_encrypt(data,key,iv,aad);print("tag="+tag.hex())
            else:
                if args.tag is None:raise ValueError("--tag required for GCM decryption")
                out=gcm_decrypt(data,key,iv,bytes.fromhex(args.tag),aad)
        print("data="+out.hex())
    except ValueError as exc:parser.error(str(exc))

if __name__=="__main__":main()
