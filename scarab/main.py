"""`libscarab` Python wrapper"""

from ctypes import c_int, c_ulong

from .loader import Library
from .types import make_c_mpz_t, clear_c_mpz_t, assign_c_mpz_t, compare_c_mpz_t, \
                   make_c_fhe_pk_t, clear_c_fhe_pk_t, \
                   make_c_fhe_sk_t, clear_c_fhe_sk_t


lib_scarab = Library.load('scarab')


class EncryptedBit(object):

    """Encrypted bit"""

    def __init__(self, pk, value):
        """Create encrypted bit

        :param pk: :class:`~PrivateKey` object
        :param value: initialized mpz_t object
        """
        self._pk = pk
        self._as_parameter_ = value

    def __xor__(self, other):
        """Homomorphic XOR"""
        c = make_c_mpz_t()
        lib_scarab.fhe_add(c, self, other, self._pk)
        return EncryptedBit(self._pk, c)

    def __and__(self, other):
        """Homomorphic AND"""
        c = make_c_mpz_t()
        lib_scarab.fhe_mul(c, self, other, self._pk)
        return EncryptedBit(self._pk, c)

    def __del__(self):
        """Clear the mpz_t value"""
        clear_c_mpz_t(self)


class EncryptedArray(object):

    """Encrypted array (ciphertext)"""

    def __init__(self, n, pk, array=None):
        """Construct empty array

        :param n:     array size
        :param pk:    :class:`~PublicKey` object
        :param array: list of initialized mpz_t objects
        """
        self._pk = pk

        if array is None:
            self._array = [make_c_mpz_t() for bit in range(n)]
        else:
            self._array = array

        self._n  = n  # Size
        self._k  = 0  # Iterator

    def __getitem__(self, i):
        """Getter

        :rtype: :class:`~EncryptedBit` object
        """
        c = self._array[i]
        b = make_c_mpz_t()
        assign_c_mpz_t(b, c)
        return EncryptedBit(self._pk, b)

    def __setitem__(self, i, value):
        """Setter

        :param value: mpz_t or :class:`~EncryptedBit` object
        """
        if isinstance(value, EncryptedBit):
            b = value._as_parameter_
            clear_c_mpz_t(self._array[i])
            assign_c_mpz_t(self._array[i], b)
        else:
            self._array[i] = value

    def __next__(self):
        """Iterator"""
        if self._k >= self._n:
            raise StopIteration()
        else:
            current = self.__getitem__[self._k]
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
            lib_scarab.fhe_add(c, a, b, self._pk)
            raw_results.append(c)
        result = EncryptedArray(len(raw_results), self._pk, array=raw_results)
        result._array = raw_results
        return result

    def __and__(self, other_array):
        """Homomorphic bitwise AND"""
        raw_results = []
        for a, b in zip(self._array, other_array):
            c = make_c_mpz_t()
            lib_scarab.fhe_mul(c, a, b, self._pk)
            raw_results.append(c)
        result = EncryptedArray(len(raw_results), self._pk, array=raw_results)
        result._array = raw_results
        return result

    # def __add__(self, other_array):
    #     """Homomorphic full addition with carry"""
    #     # import ipdb;ipdb.set_trace()
    #     raw_results = []
    #     d = make_c_mpz_t() # c_in
    #     c = make_c_mpz_t() # c_out
    #     for a, b in zip(self._array, other_array):
    #         s = make_c_mpz_t() # sum
    #         lib_scarab.fhe_fulladd(s, c, a, b, d, self.pk.raw)
    #         assign_c_mpz_t(d, c)
    #         raw_results.append(s)
    #     if compare_c_mpz_t(d, c_ulong(0)) != 0:
    #         raw_results.append(c)
    #     result = EncryptedArray(len(raw_results), self.pk, array=raw_results)
    #     result._array = raw_results
    #     return result

    def __del__(self):
        """Clear array of mpz_t"""
        for c in self._array:
            clear_c_mpz_t(c)


class PublicKey(object):

    """Public Key"""

    def __init__(self, pk):
        """Create PublicKey object from raw public key

        Should be constructed with :func:`~generate_pair`

        :param pk: initialized fhe_pk_t object
        """
        self._as_parameter_ = pk

    def encrypt(self, plain):
        """Encrypt message bit-by-bit

        :param plain : plaintext bit array or a single bit
        :type plain  : list of integers or integer
        :rtype       : :class:`~EncryptedArray` or :class:`~EncryptedBit`
                       object
        """
        if hasattr(plain, '__len__'): # and len(plain) > 1:
            encrypted_array = EncryptedArray(len(plain), self)
            for i, bit in enumerate(plain):
                c = make_c_mpz_t()
                lib_scarab.fhe_encrypt(c, self, int(bit))
                encrypted_array[i] = c
            return encrypted_array
        else:
            c = make_c_mpz_t()
            lib_scarab.fhe_encrypt(c, self, int(plain))
            return EncryptedBit(self, c)

    def __del__(self):
        """Clear key"""
        clear_c_fhe_pk_t(self)


class PrivateKey(object):

    """Private Key"""

    def __init__(self, sk):
        """Create PrivateKey object from raw private key

        Should be constructed with :func:`~generate_pair`

        :param sk: initialized fhe_sk_t object
        """
        self._as_parameter_ = sk

    def decrypt(self, encrypted):
        """Decrypt the encrypted array

        :param encrypted: :class:`~EncryptedArray` or :class:`~EncryptedBit`
                          object
        :returns        : decrypted ciphertext
        :rtype          : list of integers or integer
        """
        if hasattr(encrypted, '__len__') and len(encrypted) > 1:
            bits = [c_int() for enc_bit in encrypted]
            for i, enc_bit in enumerate(encrypted):
                bits[i] = int(lib_scarab.fhe_decrypt(enc_bit, self))
            return bits

        else:
            return int(lib_scarab.fhe_decrypt(encrypted, self))

    def __del__(self):
        """Clear key"""
        clear_c_fhe_sk_t(self)


def generate_pair():
    """Generate public and private keypair

    >>> pk, sk = generate_pair()
    >>> sk.decrypt(pk.encrypt(1))
    1
    >>> sk.decrypt(pk.encrypt(0))
    0
    """
    pk, sk = make_c_fhe_pk_t(), make_c_fhe_sk_t()
    lib_scarab.fhe_keygen(pk, sk)
    return PublicKey(pk), PrivateKey(sk)
