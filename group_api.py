import os
import json
from wrap_openssl import OpenSSLWrapper
from crypto import UserKeyLoader
from clouds import DropboxCloud
from bdcst_enc import BroadcastEncryption
import pickle

class GroupApi:

    @staticmethod
    def bdcst_file(n):
        return n + ".broadcast.manifest.txt"

    def __init__(self):
        self.bdcst = BroadcastEncryption()

    def create_group(self, group_name, members):
        (c, k) = self.bdcst.encrypt(members)
        print(members)
        print(c)
        m = pickle.dumps((members, c))
        DropboxCloud.put_overwrite_b(GroupApi.bdcst_file(group_name), m)
        print("Encrypt Key : ", k)

    def retreive_group(self, group_name):
        m = DropboxCloud.get(GroupApi.bdcst_file(group_name))
        (members, c) = pickle.loads(m)
    #    print(members)
    #    print(c)
        k = self.bdcst.decrypt(members, "alice", c)
        print('Decrypt is done')
        print("Group Key : ", k)

class AdminGroupManagement:

    def __init__(self, admin_name):
        self.members = []
        self.crypt = OpenSSLWrapper()
        self.admin_pri_key = UserKeyLoader.pri_key(admin_name)
        self.new_group = False

    def load_group(self, name):
        # there is an existing group key, go and fetch
        pass

    def create_group(self, name, members):
        self.new_group = True
        self.aes_key = os.urandom(32)
        self.members.extend(members)
        self.name = name

    def add_users_to_group(self, name, members):
        self.members.extend(members)

    def push_changes(self):
        m = str.encode(json.dumps(self.members))
        c = self.crypt.aes_encrypt(m, self.aes_key)
        p = self.crypt.rsa_sign(c, self.admin_pri_key)
        DropboxCloud.put_overwrite_b(self.name + ".members.manifest.txt", p)

        if self.new_group:
            # put also group key block
            k = self.crypt.broadcast_encrypt(self.aes_key, self.members)
            ks = self.crypt.rsa_sign(k, self.admin_pri_key)
            DropboxCloud.put_overwrite_b(self.name + ".key.manifest.txt", ks)

def main():
    g = GroupApi()
    g.create_group("friends", ["alice", "bob", "steve"])
    g.retreive_group("friends")

if __name__ == "__main__":
    main()
