"""Educational AES modes. Not for production use; GCM uses GHASH + tag verification."""
import hmac
from .aes_encrypt import aes_encrypt
from .aes_decrypt import aes_decrypt

BLOCK = 16

def xor(a,b):
    return bytes(x^y for x,y in zip(a,b))

def pad(data):
    n=BLOCK-len(data)%BLOCK
    return data+bytes([n])*n

def unpad(data):
    if not data or len(data)%BLOCK: raise ValueError('Invalid padded data')
    n=data[-1]
    if not 1<=n<=BLOCK or data[-n:]!=bytes([n])*n: raise ValueError('Invalid padding')
    return data[:-n]

def blocks(data):
    return (data[i:i+BLOCK] for i in range(0,len(data),BLOCK))

def ecb_encrypt(data,key):
    return b''.join(aes_encrypt(b,key) for b in blocks(pad(data)))

def ecb_decrypt(data,key):
    if not data or len(data)%BLOCK: raise ValueError('Invalid ciphertext length')
    return unpad(b''.join(aes_decrypt(b,key) for b in blocks(data)))

def cbc_encrypt(data,key,iv):
    if len(iv)!=BLOCK: raise ValueError('IV must be 16 bytes')
    previous=iv; out=b''
    for block in blocks(pad(data)):
        previous=aes_encrypt(xor(block,previous),key);out+=previous
    return out

def cbc_decrypt(data,key,iv):
    if len(iv)!=BLOCK or not data or len(data)%BLOCK: raise ValueError('Invalid IV or ciphertext')
    previous=iv;out=b''
    for block in blocks(data):
        out+=xor(aes_decrypt(block,key),previous);previous=block
    return unpad(out)

def ctr_crypt(data,key,nonce):
    """Nonce is the initial 16-byte counter block, big-endian; never reuse with a key."""
    if len(nonce)!=16: raise ValueError('Initial counter must be 16 bytes')
    counter=int.from_bytes(nonce,'big');out=bytearray()
    if (len(data)+15)//16 > (1<<128)-counter: raise ValueError('Counter would wrap')
    for block in blocks(data):
        stream=aes_encrypt(counter.to_bytes(16,'big'),key)
        out.extend(xor(block,stream));counter+=1
    return bytes(out)

def _gf128_mul(x,y):
    z=0;v=y
    for i in range(128):
        if (x>>(127-i))&1:z^=v
        v=(v>>1)^(0xe1000000000000000000000000000000 if v&1 else 0)
    return z

def _ghash(h,aad,ciphertext):
    y=0
    def padded(data):return data+b'\x00'*((-len(data))%16)
    data=padded(aad)+padded(ciphertext)+(len(aad)*8).to_bytes(8,'big')+(len(ciphertext)*8).to_bytes(8,'big')
    for block in blocks(data):y=_gf128_mul(y^int.from_bytes(block,'big'),h)
    return y.to_bytes(16,'big')

def _inc32(counter):
    n=(int.from_bytes(counter[-4:],'big')+1)%(1<<32)
    return counter[:12]+n.to_bytes(4,'big')

def _gcm_counter_crypt(data,key,j0):
    if (len(data)+15)//16 >= (1<<32)-1:raise ValueError('GCM input too long')
    counter=j0;out=bytearray()
    for block in blocks(data):
        counter=_inc32(counter)
        out.extend(xor(block,aes_encrypt(counter,key)))
    return bytes(out)

def _j0(key,nonce,h):
    if len(nonce)==12:return nonce+b'\x00\x00\x00\x01'
    return _ghash(h,b'',nonce)

def gcm_encrypt(data,key,nonce,aad=b''):
    if not nonce:raise ValueError('Nonce must not be empty')
    h=int.from_bytes(aes_encrypt(bytes(16),key),'big');j0=_j0(key,nonce,h)
    ct=_gcm_counter_crypt(data,key,j0)
    tag=xor(aes_encrypt(j0,key),_ghash(h,aad,ct))
    return ct,tag

def gcm_decrypt(ciphertext,key,nonce,tag,aad=b''):
    if len(tag)!=16 or not nonce:raise ValueError('Invalid tag or nonce')
    h=int.from_bytes(aes_encrypt(bytes(16),key),'big');j0=_j0(key,nonce,h)
    expected=xor(aes_encrypt(j0,key),_ghash(h,aad,ciphertext))
    if not hmac.compare_digest(expected,tag):raise ValueError('Authentication failed')
    return _gcm_counter_crypt(ciphertext,key,j0)
