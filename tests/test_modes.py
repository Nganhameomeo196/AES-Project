import unittest
from src import modes

class ModeTests(unittest.TestCase):
    def setUp(self):self.key=bytes(range(16));self.data=b'Hello AES modes! '*3
    def test_ecb(self):self.assertEqual(modes.ecb_decrypt(modes.ecb_encrypt(self.data,self.key),self.key),self.data)
    def test_cbc(self):self.assertEqual(modes.cbc_decrypt(modes.cbc_encrypt(self.data,self.key,bytes(16)),self.key,bytes(16)),self.data)
    def test_ctr(self):self.assertEqual(modes.ctr_crypt(modes.ctr_crypt(self.data,self.key,bytes(16)),self.key,bytes(16)),self.data)
    def test_gcm(self):
        nonce=b'nonce-12byte';ct,tag=modes.gcm_encrypt(self.data,self.key,nonce,b'header')
        self.assertEqual(modes.gcm_decrypt(ct,self.key,nonce,tag,b'header'),self.data)
        with self.assertRaises(ValueError):modes.gcm_decrypt(ct,self.key,nonce,bytes(16),b'header')
    def test_nist_gcm_empty(self):
        ct,tag=modes.gcm_encrypt(b'',bytes(16),bytes(12))
        self.assertEqual(ct,b'');self.assertEqual(tag.hex(),'58e2fccefa7e3061367f1d57a4e7455a')
    def test_nist_gcm_block(self):
        ct,tag=modes.gcm_encrypt(bytes(16),bytes(16),bytes(12))
        self.assertEqual(ct.hex(),'0388dace60b6a392f328c2b971b2fe78')
        self.assertEqual(tag.hex(),'ab6e47d42cec13bdf53a67b21257bddf')
    def test_padding_reject(self):
        with self.assertRaises(ValueError):modes.unpad(b'bad')
if __name__=='__main__':unittest.main()
