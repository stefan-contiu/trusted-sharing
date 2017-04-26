from wrap_openssl import OpenSSLWrapper

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
            DropboxCloud.put_overwrite_b(self.name + ".key.manifest.txt", k)
