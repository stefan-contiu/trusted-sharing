import os
from cryptography.hazmat.backends.openssl import backend as openssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import *


class UserKeyLoader:

    path = 'rsa_keys/'

    @staticmethod
    def pri_key(user):
        with open(UserKeyLoader.path + user + '.pri', 'rb') as fkey:
            key_data = fkey.read()
        pri_key = load_pem_private_key(key_data, password=None, backend=openssl)
        return pri_key

    @staticmethod
    def pub_key(user):
        with open(UserKeyLoader.path + user + '.pub', 'rb') as fkey:
            key_data = fkey.read()
        pub_key = load_pem_public_key(key_data, backend=openssl)
        return pub_key

class PubKeysLookup:

    path = 'rsa_keys/'
    keys = {}

    @staticmethod
    def load():
        for file in os.listdir(PubKeysLookup.path):
            if file.endswith(".pub"):
                user = os.path.splitext(file)[0]
                PubKeysLookup.keys[user] = UserKeyLoader.pub_key(user)
        return len(PubKeysLookup.keys.keys())

    def get(user):
        return PubKeysLookup.k[user]

class AONT:

    @staticmethod
    def transform(self, s):
        # generate a random key
        # alter the whole s by rand key
        #
        pass

    @staticmethod
    def combine(self, package, stub):
        pass

class BroadcastEncryption:

    @staticmethod
    def encrypt(self, plaintext, users_keys):
        return plaintext

    @staticmethod
    def decrypt(self, plaintext, user_key):
        return plaintext
