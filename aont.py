from wrap_openssl import OpenSSLWrapper
import random
from os import urandom

class AONT:

    def __init__(self):
        self.crypto = OpenSSLWrapper()
        self.block_size = 8 * 1024 # 64 KB

    @staticmethod
    def xor_blocks(b1, b2):
        assert len(b1) == len(b2)
        x = bytearray(len(b1))
        for i in range(len(b1)):
            x[i] = b1[i] ^ b2[i]
        return x

    def aont(self, f):
        chunks = []

        # generate a random key
        rk = self.crypto.random(32)
        last_block = rk

        # split into blocks, encrypt each block and chain xor hash the ciphers
        while True:
            block_data = f.read(self.block_size)
            if not block_data:
                break
            block_cipher = self.crypto.aes_encrypt(block_data, rk)
            chunks.append(block_cipher)

            block_cipher_sha = self.crypto.sha256(block_cipher)
            last_block = AONT.xor_blocks(block_cipher_sha, last_block)

        chunks.append(last_block)
        return chunks

    def aont_safeguard(self, local_file_name, safeguard_key):
        # split in aont blocks
        f = open(local_file_name, 'rb')
        b = self.aont(f)
        f.close()

        # randomly pick a block
        i = random.randint(0, len(b) - 1)

        # encrypt it using the safeguard key
        b[i] = self.crypto.aes_encrypt(bytes(b[i]), safeguard_key)
        return (b, i)

    def reverse_aont_safeguard(self, b, safeguard_index, safeguard_key):
        # decrypt the safeguard
        b[safeguard_index] = self.crypto.aes_decrypt(b[safeguard_index],
            safeguard_key)

        # chain hash the blocks to find the random key
        rk = b[len(b) - 1]
        for i in range(len(b) - 1):
            block_cipher_sha = self.crypto.sha256(b[i])
            rk = AONT.xor_blocks(block_cipher_sha, rk)

        # join blocks to get file
        f = b""
        for i in range(len(b) - 1):
            p = self.crypto.aes_decrypt(b[i], bytes(rk))
            f = f + p

        return f

def bvt():
    a = AONT()
    k = urandom(32)
    (b, i) = a.aont_safeguard("test.pdf", k)
    f = a.reverse_aont_safeguard(b, i, k)
    with open("test2.pdf", "wb") as out:
        out.write(f)

def main():
    bvt()

if __name__ == "__main__":
    main()
