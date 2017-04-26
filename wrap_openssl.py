
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends.openssl import backend as openssl
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.asymmetric.padding import PSS, OAEP, MGF1


class OpenSSLWrapper:
    backend = openssl
    def __init__(self):
        pass

    def aes_encrypt(self, s, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv),
            backend=OpenSSLWrapper.backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(s) + encryptor.finalize()
        return iv + ct

    def aes_decrypt(self, s, key):
        iv = s[:16]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv),
            backend=OpenSSLWrapper.backend)
        decryptor = cipher.decryptor()
        p = decryptor.update(s[16:]) + decryptor.finalize()
        return p

    def rsa_sign(self, msg, user_pri_key):
        signer = user_pri_key.signer(
            PSS(mgf=MGF1(SHA512()),
            salt_length=PSS.MAX_LENGTH), SHA512())
        signer.update(msg)
        signature = signer.finalize()
        sig_length = (len(signature)).to_bytes(4, byteorder='big')
        return sig_length + signature + msg

    def rsa_verify(self, msg, user_pub_key):
        sig_length_bytes = msg[:4]
        sig_length = int.from_bytes(sig_length_bytes, byteorder='big')
        signature = msg[4:4+sig_length]
        s = msg[4+sig_length:]
        verifier = user_pub_key.verifier(
            signature,
            PSS(mgf=MGF1(SHA512()), salt_length=PSS.MAX_LENGTH), SHA512())
        verifier.update(s)
        verifier.verify()
        return s

    def broadcast_encrypt(self, s, users):
        return s

    def broadcast_decrypt(self, s, user):
        return s

class CryptoOps:

    def __init__(self, user_pri_key):
        self.openSSL = OpenSSLWrapper()

    def encrypt_sign(s, aes_key):
        c = self.openSSL.aes_encrypt(s, aes_key)
        p = openSSL.rsa_sign(c, user_pri_key)
