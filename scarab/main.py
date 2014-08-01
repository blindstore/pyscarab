"""`libscarab` Python wrapper"""

from ctypes import c_int

from .loader import Library
from .types import make_c_mpz_t, clear_c_mpz_t, \
                   make_c_fhe_pk_t, clear_c_fhe_pk_t, \
                   make_c_fhe_sk_t, clear_c_fhe_sk_t


lib_scarab = Library.load('scarab')


class EncryptedArray(object):

    """Encrypted array (ciphertext)"""

    def __init__(self, n, pk, fill=True):
        """Construct empty array

        :param n:    array size
        :param pk:   :class:`~PublicKey` object
        :param fill: if True, fills an array with c_mpz_t instances
        """
        self.pk = pk

        if fill:
            self._array = [make_c_mpz_t() for bit in range(n)]
        else:
            self._array = []

        self._n  = n  # Size
        self._k  = 0  # Iterator

    def __getitem__(self, i):
        """Get i-th element"""
        return self._array[i]

    def __setitem__(self, i, _):
        """Ignore setter

        FIXME: Does this make sense?
        """
        pass

    def __next__(self):
        """Iterator"""
        if self._k >= self._n:
            raise StopIteration()
        else:
            current = self._array[self._k]
            self._k += 1
            return current

    def next(self):
        """Iterator for Python 2"""
        return self.__next__()

    # def recrypt(self):
    #     """Recrypt ciphertext"""
    #     recrypted_array = []
    #     for c in self._array:
    #         lib_scarab.fhe_recrypt(c, self.pk.raw)
    #         recrypted_array.append(c)
    #     self._array = recrypted_array

    def __len__(self):
        """Array size"""
        return self._n

    def __xor__(self, other_array):
        """Homomorphic bitwise XOR"""
        raw_results = []
        for a, b in zip(self._array, other_array):
            c = make_c_mpz_t()
            lib_scarab.fhe_add(c, a, b, self.pk.raw)
            raw_results.append(c)
        result = EncryptedArray(len(raw_results), self.pk, fill=False)
        result._array = raw_results
        return result

    def __and__(self, other_array):
        """Homomorphic bitwise AND"""
        raw_results = []
        for a, b in zip(self._array, other_array):
            c = make_c_mpz_t()
            lib_scarab.fhe_mul(c, a, b, self.pk.raw)
            raw_results.append(c)
        result = EncryptedArray(len(raw_results), self.pk, fill=False)
        result._array = raw_results
        return result

    def __add__(self, other_array):
        """Homomorphic addition with carry"""
        pass

    def __del__(self):
        """Clear array of mpz_t"""
        for c in self._array:
            clear_c_mpz_t(c)


class PublicKey(object):

    """Public Key"""

    def __init__(self, pk):
        """Create PublicKey object from raw public key

        Should be constructed with :func:`~generate_pair`
        """
        self.raw = pk

    def encrypt(self, bits):
        """Encrypt message bit-by-bit

        :param bits: plaintext bit array
        :rtype: encrypted array
        """
        encrypted_array = EncryptedArray(len(bits), self)
        for i, bit in enumerate(bits):
            lib_scarab.fhe_encrypt(encrypted_array[i], self.raw, int(bit))
        return encrypted_array

    def __del__(self):
        """Clear key"""
        clear_c_fhe_pk_t(self.raw)


class PrivateKey(object):

    """Private Key"""

    def __init__(self, sk):
        """Create PrivateKey object from raw private key

        Should be constructed with :func:`~generate_pair`
        """
        self.raw = sk

    def decrypt(self, encrypted_array):
        """Decrypt the encrypted array

        :param encrypted_array: encrypted array
        :rtype: plaintext bit array
        """
        bits = [c_int() for enc_bit in encrypted_array]
        for i, enc_bit in enumerate(encrypted_array):
            bits[i] = int(lib_scarab.fhe_decrypt(enc_bit, self.raw))
        return bits

    def __del__(self):
        """Clear key"""
        clear_c_fhe_sk_t(self.raw)


def generate_pair():
    """Generate public and private keypair"""
    pk, sk = make_c_fhe_pk_t(), make_c_fhe_sk_t()
    lib_scarab.fhe_keygen(pk, sk)
    return PublicKey(pk), PrivateKey(sk)
