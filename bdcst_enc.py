from ctypes import cdll
from ctypes import c_int, c_char_p, byref, create_string_buffer, POINTER

lib = cdll.LoadLibrary('./pbc_bce-0.0.1/bdcst.so')

class BroadcastEncryption(object):
    def __init__(self):
        pass

    def setup(self):
        lib.one_time_init()

    def encrypt(self):
        users = (c_int*3)()
        users[0] = 1
        users[1] = 2
        users[2] = 3

        k = create_string_buffer(256)
        c = create_string_buffer(256)
        k_len = (c_int*1)()
        c_len = (c_int*1)()

        lib.broadcast_encrypt_group(users, 3, k, k_len, c, c_len)

        kb = bytearray(k)
        #cb = bytearray(c)
        print(kb[:k_len[0]])

        #print(cb)

    def decrypt(self):
        pass

def main():
  b = BroadcastEncryption()
  #b.setup()
  b.encrypt()
  print("Check timestamp !")

if __name__ == "__main__":
    print("Calling into C code")
    main()
