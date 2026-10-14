"""CLI subprocess tests ensure actual entrypoint and error handling work."""
import subprocess
import sys
import unittest

KEY='000102030405060708090a0b0c0d0e0f'
PT='00112233445566778899aabbccddeeff'
CT='69c4e0d86a7b0430d8cdb78070b4c55a'

class CliTests(unittest.TestCase):
    def invoke(self,*args):
        return subprocess.run([sys.executable,'-m','src.cli',*args],capture_output=True,text=True)

    def test_encrypt(self):
        p=self.invoke('encrypt','--key',KEY,'--data',PT)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('data='+CT,p.stdout)

    def test_decrypt(self):
        p=self.invoke('decrypt','--key',KEY,'--data',CT)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('data='+PT,p.stdout)

    def test_trace(self):
        p=self.invoke('trace','--key',KEY,'--data',PT)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('MixColumns',p.stdout)

    def test_invalid_key(self):
        p=self.invoke('encrypt','--key','ab','--data',PT)
        self.assertNotEqual(p.returncode,0)
        self.assertIn('Key must',p.stderr)

if __name__=='__main__':unittest.main()
