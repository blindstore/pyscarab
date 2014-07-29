"""libscarab Python wrapper"""

import os
import ctypes


path = os.path.abspath(__file__)
project_path = os.path.dirname(os.path.dirname(path))
scarab = ctypes.cdll.LoadLibrary(os.path.join(project_path,
    'lib/scarab/build/libscarab.so'))


class PublicKey(object):

    """Public Key"""

    def __init__(self, pk):
        """Create PublicKey object from raw public key"""
        self.raw = pk

    def encrypt(self, bits):
        """Encrypt message bit-by-bit

        :param bits: Plaintext bit array
        :rtype: Encrypted bit array
        """
        encrypted_array = [scarab.mpz_t() for bit in bits]
        for i, bit in enumerate(m):
            scarab.fhe_encrypt(encrypted_array[i], self.raw, int(bit))
        return encrypted_array


class PrivateKey(object):

    """Private Key"""

    def __init__(self, sk):
        """Create PrivateKey object from raw private key"""
        self.raw = sk

    def decrypt(self, encrypted_array):
        """Decrypt the encrypted array

        :param encrypted_array: Encrypted bit array
        :rtype: Plaintext bit array
        """
        bits = [ctypes.c_int() for enc_bit in encrypted_array]
        for i, enc_bit in enumerate(encrypted_array):
            bits[i] = int(scarab.fhe_decrypt(enc_bit, self.raw))
        return bits


class EncryptedArray(object):

    """Encrypted array (ciphertext)"""

    def __init__(self, n):
        """Construct empty array

        :param n: Encrypted array size
        """
        self.array = [scarab.mpz_t() for bit in range(n)]
        self.n = n  # Size
        self.k = 0  # Iterator

    def __getitem__(self, i):
        """Get i-th element"""
        return self.array[i]

    def __setitem__(self, i, value):
        """Set i-th element"""
        self.array[i] = value

    def __next__(self):
        """Iterator"""
        if self.k >= self.n:
            raise StopIteration()
        else:
            current = self.array[self.k]
            self.k += 1
            return current

    def next(self):
        """Iterator for Python 2"""
        return self.__next__()

    def __len__(self):
        """Array size"""
        return self.n

    def __add__(self):
        """Homomorphic addition"""
        pass

    def __mul__(self):
        """Homomorphic multiplication"""
        pass


def generate_pair():
    """Generate public and private keypair"""
    pk, sk = scarab.fhe_pk_t(), scarab.fhe_sk_t()
    scarab.fhe_keygen(pk, sk)
    return PublicKey(pk), PrivateKey(sk)
