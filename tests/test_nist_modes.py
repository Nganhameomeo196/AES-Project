"""NIST SP 800-38A ECB/CBC/CTR vectors; GCM SP 800-38D example with AAD."""
import unittest
from src.modes import ecb_encrypt, ecb_decrypt, cbc_encrypt, cbc_decrypt, ctr_crypt, gcm_encrypt, gcm_decrypt

PT=bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51'
                 '30c81c46a35ce411e5fbc1191a0a52ef'
                 'f69f2445df4f9b17ad2b417be66c3710')
IV=bytes.fromhex('000102030405060708090a0b0c0d0e0f')
CTR=bytes.fromhex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
VECTORS=[
('2b7e151628aed2a6abf7158809cf4f3c','3ad77bb40d7a3660a89ecaf32466ef97','7649abac8119b246cee98e9b12e9197d','874d6191b620e3261bef6864990db6ce'),
('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b','bd334f1d6e45f25ff712a214571fa5cc','4f021db243bc633d7178183a9fa071e8','1abc932417521ca24f2b0459fe7e6e0b'),
('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4','f3eed1bdb5d2a03c064b5a7e3db181f8','f58c4c04d6e5f1ba779eabfb5f7bfbd6','601ec313775789a5b7a7f504bbf3d228'),
]

class NistModes(unittest.TestCase):
    def test_sp800_38a_ecb(self):
        for key, expected, _, _ in VECTORS:
            with self.subTest(key_bits=len(key)*4):
                ct=ecb_encrypt(PT[:16],bytes.fromhex(key))
                self.assertEqual(ct[:16].hex(),expected)
                self.assertEqual(ecb_decrypt(ct,bytes.fromhex(key)),PT[:16])

    def test_sp800_38a_cbc(self):
        for key, _, expected, _ in VECTORS:
            with self.subTest(key_bits=len(key)*4):
                ct=cbc_encrypt(PT[:16],bytes.fromhex(key),IV)
                self.assertEqual(ct[:16].hex(),expected)
                self.assertEqual(cbc_decrypt(ct,bytes.fromhex(key),IV),PT[:16])

    def test_sp800_38a_ctr(self):
        for key, _, _, expected in VECTORS:
            with self.subTest(key_bits=len(key)*4):
                ct=ctr_crypt(PT[:16],bytes.fromhex(key),CTR)
                self.assertEqual(ct.hex(),expected)
                self.assertEqual(ctr_crypt(ct,bytes.fromhex(key),CTR),PT[:16])


    def test_sp800_38a_four_blocks(self):
        vectors = [
            ("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
             "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
             "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"),
            ("bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eefef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
             "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
             "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050"),
            ("f3eed1bdb5d2a03c064b5a7e3db181f8 591ccb10d410ed26dc5ba74a31362870 b6ed21b99ca6f4f9f153e7b1beafed1d 23304b7a39f9f3ff067d8d8f9e24ecc7",
             "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
             "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6")
        ]
        for (key_hex, _, _, _), (ecb_hex, cbc_hex, ctr_hex) in zip(VECTORS, vectors):
            key = bytes.fromhex(key_hex)
            with self.subTest(key_bits=len(key) * 8):
                self.assertEqual(ecb_encrypt(PT, key)[:len(PT)], bytes.fromhex(ecb_hex))
                self.assertEqual(cbc_encrypt(PT, key, IV)[:len(PT)], bytes.fromhex(cbc_hex))
                self.assertEqual(ctr_crypt(PT, key, CTR), bytes.fromhex(ctr_hex))
                self.assertEqual(cbc_decrypt(cbc_encrypt(PT, key, IV), key, IV), PT)

    def test_gcm_aad_multiblock(self):
        key=bytes.fromhex('feffe9928665731c6d6a8f9467308308')
        nonce=bytes.fromhex('cafebabefacedbaddecaf888')
        aad=bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
        pt=bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
                         '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
        expected_ct=bytes.fromhex('42831ec2217774244b7221b784d0d49c'
                                   'e3aa212f2c02a4e035c17e2329aca12e'
                                   '21d514b25466931c7d8f6a5aac84aa05'
                                   '1ba30b396a0aac973d58e091')
        ct,tag=gcm_encrypt(pt,key,nonce,aad)
        self.assertEqual(ct,expected_ct)
        self.assertEqual(tag.hex(),'5bc94fbc3221a5db94fae95ae7121a47')
        self.assertEqual(gcm_decrypt(ct,key,nonce,tag,aad),pt)
        with self.assertRaises(ValueError):gcm_decrypt(ct,key,nonce,tag,aad+b'!')

if __name__=='__main__':unittest.main()
