import os
import json
from wrap_openssl import OpenSSLWrapper
from crypto import UserKeyLoader
from user_api import UserSession

from clouds import MockCloud as cloud # DropboxCloud

from bdcst_enc import BroadcastEncryption
from aont import AONT

import pickle
import uuid


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
        self.aont = AONT()

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
        self.session.groups_meta[group_name] = (members, c)
        self.session.groups_keys[group_name] = (group_broadcast_key, aes_manifest_key,
            aes_safeguard_key)
        self.session.groups_files[group_name] = {}

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

    def upload_file(self, group_name, local_file_name):
        # get group safeguard key
        (b_key, m_key, s_key) = self.session.groups_keys[group_name]

        # aont-ify
        (b, safe_index) = self.aont.aont_safeguard(local_file_name, s_key)

        # assign a random id per each block
        block_ids = []
        for i in range(len(b)):
            block_id = str(uuid.uuid4())
            cloud.put_overwrite_b(block_id, b[i])
            block_ids.append(block_id)

        # update the group files manifest
        self.session.groups_files[group_name][local_file_name] = (block_ids,
            safe_index)
        f = pickle.dumps(self.session.groups_files[group_name])

        # encrypt it and push to cloud
        cf = self.crypto.aes_encrypt(f, m_key)
        cloud.put_overwrite_b(GroupApi.manifest_file(group_name), cf)


def main():

    session = UserSession("alice")

    g = GroupApi(session)
    g.create_group("friends", ["alice", "bob", "steve"])
    g.upload_file("friends", "test.pdf")
    g.retreive_group_key("friends")

if __name__ == "__main__":
    main()
