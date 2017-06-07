from ctypes import cdll
from ctypes import c_int, c_char_p, byref, create_string_buffer, addressof
from crypto import PKI, AdminPKI
from wrap_openssl import OpenSSLWrapper

lib = cdll.LoadLibrary('./pbc_sig-0.0.8/bbs.so')



class GroupSignature(object):
    def __init__(self):
        self.openssl = OpenSSLWrapper()

    def sign(self, admin_name, data):
        pub_key = AdminPKI.get_pub()
        pri_key = AdminPKI.get_pri(admin_name)

        signature = create_string_buffer(512)
        sig_len = (c_int * 1)()
        lib.bbs_sign_raw(signature, sig_len,
            len(data), bytes(data),
            len(pub_key), bytes(pub_key),
            len(pri_key), bytes(pri_key))

        sb = bytes(signature)[:sig_len[0]]
        return sb

    def verify(self, signature, data):
        pub_key = AdminPKI.get_pub()

        r = lib.bbs_verify_raw(bytes(signature),
            len(data), bytes(data),
            len(pub_key), bytes(pub_key))

        return r

def basic_validation_test():
  g = GroupSignature()
  msg = b"This is a message"
  s = g.sign("admin1", msg)
  r = g.verify(s, msg)
  assert r == 1
  print("Group signature basic test works!")

if __name__ == "__main__":
    basic_validation_test()
