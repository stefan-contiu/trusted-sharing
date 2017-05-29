import os
import json
from wrap_openssl import OpenSSLWrapper
from crypto import UserKeyLoader
from user_api import UserSession

from clouds import MockCloud as cloud # DropboxCloud

from bdcst_enc import BroadcastEncryption
import pickle

class GroupApi:

    @staticmethod
    def bdcst_file(n):
        return n + ".broadcast.manifest.txt"

    @staticmethod
    def manifest_file(n):
        return n + ".files.manifest.txt"

    @staticmethod
    def manifest_key_file(n):
        return n + ".key.manifest.txt"

    @staticmethod
    def safeguard_key_file(n):
        return n + ".key.safeguard.txt"

    def __init__(self, session):
        self.bdcst = BroadcastEncryption()
        self.crypto = OpenSSLWrapper()
        self.session = session

    def create_group(self, group_name, members):
        # create group broadcast key
        (group_broadcast_key, c) = self.bdcst.encrypt(members)
        m = pickle.dumps((members, c))
        cloud.put_overwrite_b(GroupApi.bdcst_file(group_name), m)

        # create group aes keys and protect them
        aes_manifest_key = self.crypto.random(32)
        aes_safeguard_key = self.crypto.random(32)
        cipher_manifest_key = self.crypto.aes_encrypt(aes_manifest_key,
            group_broadcast_key)
        cipher_safeguard_key = self.crypto.aes_encrypt(aes_safeguard_key,
            group_broadcast_key)
        cloud.put_overwrite_b(GroupApi.manifest_key_file(group_name),
            cipher_manifest_key)
        cloud.put_overwrite_b(GroupApi.safeguard_key_file(group_name),
            cipher_safeguard_key)

        # push meta & keys to the user session cache
        self.session.groups_meta.add((members, c))
        self.session.groups_keys.add((group_broadcast_key, aes_manifest_key,
            aes_safeguard_key))

    def retreive_group_key(self, group_name):
        m = cloud.get(GroupApi.bdcst_file(group_name))
        (members, c) = pickle.loads(m)
        k = self.bdcst.decrypt(members, "alice", c)

        # todo : push stuff to cache

    def add_user_to_group(self, group_name, new_user_name):
        # create new group broadcast key
        # encrypt the old keys with the new broadcast
        # push everything to cloud
        pass

    def remove_user_from_group(self, group_name, user_name):
        # create new group broadcast key
        # create new manifest key
        # create new safeguard key

        # re-encrypt manifest
        # re-encrypt all group safeguards

        # push everything to cloud
        pass

    def download_file(self, file_name):
        # identify the blocks that need to be downloaded
        # download blocks
        # decrypt the safeguarded block
        # reverse AONT
        pass

    def upload_file(self, local_file_name):
        # AONTify

        # randomly choose block and encrypt with safeguard key
        # upload blocks to cloud
        # upload updated group manifest
        pass


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

    session = UserSession("alice")

    g = GroupApi(session)
    g.create_group("friends", ["alice", "bob", "steve"])
    g.retreive_group_key("friends")

if __name__ == "__main__":
    main()
