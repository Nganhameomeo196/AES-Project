import random,unittest
from src.aes_encrypt import aes_encrypt
from src.aes_decrypt import aes_decrypt
from src.key_expansion import round_keys
from src.trace import encrypt_trace,decrypt_trace
from src.modes import *
from experiments.toy_cryptanalysis import differential_table,linear_table
from experiments.avalanche import distance

class AdvancedTests(unittest.TestCase):
    def test_round_key_counts(self):
        for size,n in ((16,11),(24,13),(32,15)):
            keys=round_keys(bytes(range(size)))
            self.assertEqual(len(keys),n)
            self.assertTrue(all(len(k)==16 for k in keys))
    def test_traces(self):
        pt=bytes(range(16))
        for size in (16,24,32):
            key=bytes(range(size));ct=aes_encrypt(pt,key)
            self.assertEqual(bytes.fromhex(encrypt_trace(pt,key)[-1]["state"]),ct)
            self.assertEqual(bytes.fromhex(decrypt_trace(ct,key)[-1]["state"]),pt)
            self.assertEqual(len(encrypt_trace(pt,key)),4*(size//4+6)+1)
    def test_seeded_random_roundtrips(self):
        rng=random.Random(12345)
        for size in (16,24,32):
            for length in (0,1,15,16,17,31,32,47,64):
                key=rng.randbytes(size);data=rng.randbytes(length)
                iv=rng.randbytes(16);nonce=rng.randbytes(12);aad=rng.randbytes(7)
                self.assertEqual(ecb_decrypt(ecb_encrypt(data,key),key),data)
                self.assertEqual(cbc_decrypt(cbc_encrypt(data,key,iv),key,iv),data)
                self.assertEqual(ctr_crypt(ctr_crypt(data,key,iv),key,iv),data)
                ct,tag=gcm_encrypt(data,key,nonce,aad)
                self.assertEqual(gcm_decrypt(ct,key,nonce,tag,aad),data)
    def test_gcm_authentication_failures(self):
        key=bytes(16);nonce=bytes(12);data=b"authenticated message";aad=b"header"
        ct,tag=gcm_encrypt(data,key,nonce,aad)
        for bad_ct,bad_tag,bad_aad in ((ct,bytes([tag[0]^1])+tag[1:],aad),(bytes([ct[0]^1])+ct[1:],tag,aad),(ct,tag,b"tampered")):
            with self.assertRaises(ValueError):gcm_decrypt(bad_ct,key,nonce,bad_tag,bad_aad)
    def test_gcm_nonstandard_nonce(self):
        for nonce in (b"12345678",b"a"*20):
            key=bytes(range(32));data=b"hello AES GCM";ct,tag=gcm_encrypt(data,key,nonce,b"aad")
            self.assertEqual(gcm_decrypt(ct,key,nonce,tag,b"aad"),data)
    def test_ctr_overflow(self):
        with self.assertRaises(ValueError):ctr_crypt(b"x"*17,bytes(16),b"\xff"*16)
    def test_padding_rejection(self):
        for invalid in (b"",bytes(16),b"a"*15):
            with self.assertRaises(ValueError):unpad(invalid)
    def test_toy_tables(self):
        ddt=differential_table();lat=linear_table()
        self.assertTrue(all(sum(row)==16 for row in ddt))
        self.assertEqual(ddt[0][0],16)
        self.assertEqual(lat[0][0],16)
        self.assertEqual(distance(bytes(16),bytes([255])*16),128)

if __name__=="__main__":unittest.main()
