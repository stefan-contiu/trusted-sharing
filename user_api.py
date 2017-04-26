import json
import uuid
import os.path

from wrap_openssl import CryptoOps
from clouds import DropboxCloud

class User:

    def __init__(self, user_id, pri_key, pub_key):
        self._user_id = user_id
        self._pub_key = pub_key
        self._pri_key = pri_key
        self._current_path = os.path.dirname(os.path.realpath(__file__))
        self._crypto = CryptoOps(pri_key)

    def download_files(self, files):
        file_manifest = DropboxCloud.get(self._user_id + ".manifest.txt")
        if file_manifest:
            fm = FileManifest(self._user_id, file_manifest.decode())
        else:
            #print("Error : User does not have any uploaded files yet")
            pass

        for f in files:
            file_name_on_cloud = fm.files[f]['enc_file_name']
            # print('Downloading ', ccolor.wrap(f))
            file_content = DropboxCloud.get(file_name_on_cloud)
            local_file = open(f, "wb")
            local_file.write(file_content)
            local_file.close()

    def upload_files(self, files):
        file_manifest = DropboxCloud.get(self._user_id + ".manifest.txt")
        if file_manifest:
            fm = FileManifest(self._user_id, file_manifest.decode())
        else:
            fm = FileManifest(self._user_id, None)
        for file_name in files:
            enc_file_name = str(uuid.uuid4())
            enc_key = os.urandom(32)
            abs_path_f = os.path.join(self._current_path, file_name)
            f_content = open(abs_path_f, "rb")
            data = f_content.read()
            DropboxCloud.put_overwrite_b(enc_file_name, data)
            f_content.close()
            fm.add_file(file_name, enc_file_name, enc_key, len(data))
        DropboxCloud.put_overwrite(self._user_id + ".manifest.txt", fm.serialize())

    def list_files(self):
        file_manifest = DropboxCloud.get(self._user_id + ".manifest.txt")
        if file_manifest:
            fm = file_manifest.decode()
            files = json.loads(fm)
            return files
        else:
            return None

    def share_files(self, files, group):
        # get group data
        group_members = DropboxCloud.get(group + ".members.manifest.txt")
        group_key = DropboxCloud.get(group + ".key.manifest.txt")
        group_files = DropboxCloud.get(group + ".files.manifest.txt")

        # verify signatures
        # broadcast decrypt group_key
        # use the key to decrypt group_members and group_files

    def clear_all(self):
        DropboxCloud.clear()


class FileManifest:

    def __init__(self, user_id, content):
        self.user_id = user_id
        if content:
            self.files = json.loads(content)
        else :
            self.files = {}

    def add_file(self, file_name, enc_file_name, enc_key, size):
        self.files[file_name] = { 'enc_file_name' : enc_file_name,
            'file_key' : enc_key.hex(),
            'file_hash' : '',
            'size' : size }

    def serialize(self):
        return json.dumps(self.files)
