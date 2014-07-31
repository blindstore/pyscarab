"""`libscarab` Python wrapper"""

from ctypes import c_int

from loader import ScarabLoader
from typedefs import c_mpz_t, c_fhe_sk_t, c_fhe_pk_t
# from utils import fhe_pk_t_init, fhe_sk_t_init, mpz_init


load_scarab = ScarabLoader()
scarab = load_scarab()


class EncryptedArray(object):

    """Encrypted array (ciphertext)"""

    def __init__(self, n, pk, fill=True):
        """Construct empty array

        :param n:    array size
        :param pk:   :class:`~PublicKey` object
        :param fill: if True, fills an array with mpz_t instances
        """
        self.pk = pk

        # FIXME: Leaks memory (proper init and clear needed)
        if fill:
            self._array = [c_mpz_t() for bit in range(n)]
        else:
            self._array = []

        self._n  = n  # Size
        self._k  = 0  # Iterator

    def __getitem__(self, i):
        """Get i-th element"""
        return self._array[i]

    def __setitem__(self, i, value):
        """Set i-th element"""
        self._array[i] = value

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

    def __len__(self):
        """Array size"""
        return self._n

    def __add__(self, other_array):
        """Homomorphic addition"""
        raw_results = []
        for a, b in zip(self._array, other_array):
            # FIXME: initialize properly, damn it
            c = c_mpz_t()
            scarab.fhe_add(c, a, b, self.pk.raw)
            raw_results.append(c)
        result = EncryptedArray(len(raw_results), self.pk, fill=False)
        result._array = raw_results
        return result

    def __mul__(self):
        """Homomorphic multiplication"""
        pass


class PublicKey(object):

    """Public Key"""

    def __init__(self, pk):
        """Create PublicKey object from raw public key"""
        self.raw = pk

    def encrypt(self, bits):
        """Encrypt message bit-by-bit

        :param bits: plaintext bit array
        :rtype: encrypted array
        """
        encrypted_array = EncryptedArray(len(bits), self)
        for i, bit in enumerate(bits):
            scarab.fhe_encrypt(encrypted_array[i], self.raw, int(bit))
        return encrypted_array

    def __del__(self):
        """Clear key"""
        scarab.fhe_pk_clear(self.raw)


class PrivateKey(object):

    """Private Key"""

    def __init__(self, sk):
        """Create PrivateKey object from raw private key"""
        self.raw = sk

    def decrypt(self, encrypted_array):
        """Decrypt the encrypted array

        :param encrypted_array: encrypted array
        :rtype: plaintext bit array
        """
        bits = [c_int() for enc_bit in encrypted_array]
        for i, enc_bit in enumerate(encrypted_array):
            bits[i] = int(scarab.fhe_decrypt(enc_bit, self.raw))
        return bits

    def __del__(self):
        """Clear key"""
        scarab.fhe_sk_clear(self.raw)


def generate_pair():
    """Generate public and private keypair"""
    pk, sk = c_fhe_pk_t(), c_fhe_sk_t()
    scarab.fhe_pk_init(pk)
    scarab.fhe_sk_init(sk)
    scarab.fhe_keygen(pk, sk)
    return PublicKey(pk), PrivateKey(sk)
