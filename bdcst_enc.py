from ctypes import cdll
from ctypes import c_int, c_char_p, byref, create_string_buffer, POINTER
from crypto import PKI
from wrap_openssl import OpenSSLWrapper

lib = cdll.LoadLibrary('./pbc_bce-0.0.1/bdcst.so')

class BroadcastEncryption(object):
    def __init__(self):
        self.openssl = OpenSSLWrapper()

    def setup(self):
        lib.one_time_init()

    def encrypt(self, users):
        u = (c_int * len(users))()
        for i in range(len(users)):
            u[i] = PKI.get_index(users[i])

        k = create_string_buffer(512)
        c = create_string_buffer(512)
        k_len = (c_int * 1)()
        c_len = (c_int * 1)()

        lib.broadcast_encrypt_group(u, len(users), k, k_len, c, c_len)

        kb = bytes(k)[:k_len[0]]
        cb = bytes(c)[:c_len[0]]

        return (self.openssl.sha256(kb), cb)

    def decrypt(self, users, pri_key, c):
        pass

def main():
  b = BroadcastEncryption()
  #b.setup()
  # alice, bob, eve, steve
  u = ["alice", "steve"]
  (k, c) = b.encrypt(u)
  b.decrypt(u, bdcst_pri_key, )

if __name__ == "__main__":
    print("Calling into C code")
    main()
