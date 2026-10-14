"""Safe, educational illustrations; no practical AES key recovery."""
from src.aes_encrypt import aes_encrypt
from src.modes import ecb_encrypt,cbc_encrypt,ctr_crypt,gcm_encrypt,gcm_decrypt

def main():
    key=bytes(range(16));block=b'A'*16
    ecb=ecb_encrypt(block*4,key)
    print('ECB identical blocks:',len(set(ecb[i:i+16] for i in range(0,64,16)))==1)
    iv=bytes(16);cbc=cbc_encrypt(block*4,key,iv)
    print('CBC distinct blocks:',len(set(cbc[i:i+16] for i in range(0,64,16)))==4)
    ct=ctr_crypt(b'HELLO',key,bytes(16));modified=bytes([ct[0]^1])+ct[1:]
    print('CTR tampering flips plaintext bit:',ctr_crypt(modified,key,bytes(16))==b'IELLO')
    ct,tag=gcm_encrypt(b'HELLO',key,b'nonce-12byte')
    try:gcm_decrypt(bytes([ct[0]^1])+ct[1:],key,b'nonce-12byte',tag)
    except ValueError:print('GCM detects tampering: yes')
    # Toy brute-force over 256 candidate 128-bit keys, with a known fixed prefix.
    secret=73;target=aes_encrypt(block,bytes(15)+bytes([secret]))
    found=next(i for i in range(256) if aes_encrypt(block,bytes(15)+bytes([i]))==target)
    print('Toy restricted key search found:',found,'(NOT full AES brute force)')
    changed=bytes([block[0]^1])+block[1:]
    a=aes_encrypt(block,key);b=aes_encrypt(changed,key)
    print('Avalanche demo - differing ciphertext bits:',sum((x^y).bit_count() for x,y in zip(a,b)))
if __name__=='__main__':main()
