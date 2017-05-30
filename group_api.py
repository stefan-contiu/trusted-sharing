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
import random

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

    def add_user_to_group(self, group_name, new_user_name):
        # create new group broadcast key
        members, old_c = self.session.groups_meta[group_name]
        members.append(new_user_name)
        (group_broadcast_key, c) = self.bdcst.encrypt(members)
        m = pickle.dumps((members, c))
        cloud.put_overwrite_b(GroupApi.bdcst_file(group_name), m)

        # protect existing keys by new group broadcast key
        (old_b_key, aes_m_key, aes_s_key) = self.session.groups_keys[group_name];

        cipher_m_key = self.crypto.aes_encrypt(aes_m_key, group_broadcast_key)
        cipher_s_key = self.crypto.aes_encrypt(aes_s_key, group_broadcast_key)
        cloud.put_overwrite_b(GroupApi.manifest_key_file(group_name),
            cipher_m_key)
        cloud.put_overwrite_b(GroupApi.safeguard_key_file(group_name),
            cipher_s_key)

        # push meta & new key to the user session cache
        self.session.groups_meta[group_name] = (members, c)
        self.session.groups_keys[group_name] = (group_broadcast_key, aes_m_key,
            aes_s_key)

    def remove_user_from_group(self, group_name, user_name):

        old_safe_key = self.session.groups_keys[group_name][2]

        # create new group broadcast key
        members, old_c = self.session.groups_meta[group_name]
        members.remove(user_name)
        (group_broadcast_key, new_c) = self.bdcst.encrypt(members)

        # create new group aes keys and protect them
        aes_manifest_key = self.crypto.random(32)
        aes_safeguard_key = self.crypto.random(32)
        cipher_manifest_key = self.crypto.aes_encrypt(aes_manifest_key,
            group_broadcast_key)
        cipher_safeguard_key = self.crypto.aes_encrypt(aes_safeguard_key,
            group_broadcast_key)

        # download and re-encrypt all safeguards
        self.revoke(group_name, old_safe_key, aes_safeguard_key)

        # update session values
        self.session.groups_keys[group_name] = (group_broadcast_key,
            aes_manifest_key, aes_safeguard_key)
        self.session.groups_meta[group_name] = (members, old_c)

        # re-encrypt the file manifest
        f = pickle.dumps(self.session.groups_files[group_name])
        cf = self.crypto.aes_encrypt(f, aes_manifest_key)
        cloud.put_overwrite_b(GroupApi.manifest_file(group_name), cf)

        # push updates to the cloud
        m = pickle.dumps((members, new_c))
        cloud.put_overwrite_b(GroupApi.bdcst_file(group_name), m)

    def revoke(self, group_name, old_safe_key, new_safe_key):
        for f in self.session.groups_files[group_name]:
            (blocks, i) = self.session.groups_files[group_name][f]

            # restore the old safe block
            old_safe_block = cloud.get(blocks[i])
            dec_block = self.crypto.aes_decrypt(old_safe_block, old_safe_key)
            cloud.put_overwrite_b(blocks[i], dec_block)

            # choose a new safe block
            assert len(blocks) > 1
            new_i = i
            while new_i == i:
                new_i = random.randint(0, len(blocks) - 1)
            new_safe_block = cloud.get(blocks[new_i])
            enc_block = self.crypto.aes_encrypt(new_safe_block, new_safe_key)
            cloud.put_overwrite_b(blocks[new_i], enc_block)

            # mark the switch in the files manifest
            self.session.groups_files[group_name][f] = (blocks, new_i)

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

    def download_file(self, file_name):
        # identify the blocks that need to be downloaded
        # download blocks
        # decrypt the safeguarded block
        # reverse AONT
        pass

    def retreive_group_key(self, group_name):
        m = cloud.get(GroupApi.bdcst_file(group_name))
        (members, c) = pickle.loads(m)
        k = self.bdcst.decrypt(members, "alice", c)
        # todo : push stuff to cache



def main():

    session = UserSession("alice")
    g = GroupApi(session)
    g.create_group("friends", ["alice", "bob", "steve"])
    g.upload_file("friends", "test.pdf")
    g.upload_file("friends", "test2.pdf")
    g.remove_user_from_group("friends", "steve")


if __name__ == "__main__":
    main()
