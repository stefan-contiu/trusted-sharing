import os
from cryptography.hazmat.backends.openssl import backend as openssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import *
from collections import OrderedDict


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

class PKI:

    path = 'rsa_keys/'
    keys = OrderedDict()

    @staticmethod
    def load():
        for file in os.listdir(PKI.path):
            if file.endswith(".pub"):
                user = os.path.splitext(file)[0]
                PKI.keys[user] = UserKeyLoader.pub_key(user)
        return len(PKI.keys.keys())

    @staticmethod
    def get(user):
        if not len(PKI.keys):
            PKI.load()
        return PubKeysLookup.k[user]

    @staticmethod
    def get_index(user):
        if not len(PKI.keys):
            PKI.load()
        return list(PKI.keys.keys()).index(user) + 1

class AONT:

    @staticmethod
    def transform(self, s):
        pass
        # generate a random key
        # alter the whole s by rand key
        #


        #E1(K, XXXXXXXXXXXXXXXXXXXXXXX)
        #E2(K, Y)
        #H(XXXXXXX) ^ H(Y) ^ K


        #BE(K), FFFFFFFFFFFFFFFFFFF



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
