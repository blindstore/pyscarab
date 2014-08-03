"""`libscarab` Python wrapper"""

import json
from ctypes import c_int, c_ulong

from .loader import Library
from .types import make_c_mpz_t, clear_c_mpz_t, assign_c_mpz_t, compare_c_mpz_t, \
                   make_c_fhe_pk_t, clear_c_fhe_pk_t, \
                   make_c_fhe_sk_t, clear_c_fhe_sk_t, \
                   serialize_c_fhe_pk_t, deserialize_c_fhe_pk_t, \
                   serialize_c_mpz_t, deserialize_c_mpz_t


lib_scarab = Library.load('scarab')


class EncryptedBit(object):

    """Encrypted bit"""

    def __init__(self, pk, value):
        """Create encrypted bit

        :param pk: :class:`~PublicKey` object
        :param value: initialized mpz_t object or serialized mpz_t
        """
        self._pk = pk
        if isinstance(value, str):
            self._as_parameter_ = deserialize_c_mpz_t(value)
        else:
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

    def __add__(self, other):
        """XOR alias"""
        return self.__xor__(other)

    def __str__(self):
        """Serialize encrypted bit to string"""
        return serialize_c_mpz_t(self._as_parameter_)

    def recrypt(self, sk):
        """Recrypt a cyphertext (refreshing it)"""
        lib_scarab.fhe_recrypt(self, self._pk, sk)


class EncryptedArray(object):

    """Encrypted array (ciphertext)"""

    def __init__(self, n, pk, array=None):
        """Construct empty array

        :param n:     array size
        :param pk:    :class:`~PublicKey` object
        :param array: list of initialized mpz_t objects or serialized
                      EncryptedArray
        """
        self._pk = pk

        if array is None:
            self._array = [make_c_mpz_t() for bit in range(n)]
        else:
            if isinstance(array, str):
                stringified_array = json.loads(array)
                self._array = [deserialize_c_mpz_t(elem) \
                    for elem in stringified_array]
            else:
                self._array = array

        self._n  = n  # Size
        self._k  = 0  # Iterator

        self.__add__ = self.__xor__

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

    def recrypt(self, sk):
        """Recrypt ciphertext"""
        for c in self._array:
            lib_scarab.fhe_recrypt(c, self._pk, sk)

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

    def __add__(self, other):
        """XOR alias"""
        return self.__xor__(other)

    def __del__(self):
        """Clear array of mpz_t"""
        for c in self._array:
            clear_c_mpz_t(c)

    def __str__(self):
        """Serialize array to string"""
        serialized_array = [serialize_c_mpz_t(mpz) for mpz in self._array]
        return json.dumps(serialized_array)


class PublicKey(object):

    """Public Key"""

    def __init__(self, pk):
        """Create PublicKey object from raw public key

        Should be constructed with :func:`~generate_pair`

        :param pk: initialized fhe_pk_t object or a serialized string
        """
        if isinstance(pk, str):
            self._as_parameter_ = deserialize_c_fhe_pk_t(pk)
        else:
            self._as_parameter_ = pk

    def encrypt(self, plain, sk=None):
        """Encrypt message bit-by-bit

        :param plain : plaintext bit array or a single bit
        :type plain  : list of integers or integer
        :param sk    : secret key, if not None, uses recrypt
        :type sk     : :class:`~PrivateKey` object or None
        :rtype       : :class:`~EncryptedArray` or :class:`~EncryptedBit`
                       object
        """
        if hasattr(plain, '__len__'):

            # Prepare encrypted bits. The encrypt function
            # is deterministic, so we can reuse them if
            # we are not using recryption
            encrypted_zero = make_c_mpz_t()
            encrypted_one = make_c_mpz_t()
            lib_scarab.fhe_encrypt(encrypted_zero, self, 0)
            lib_scarab.fhe_encrypt(encrypted_one, self, 1)

            encrypted_array = EncryptedArray(len(plain), self)

            for i, bit in enumerate(plain):

                c = make_c_mpz_t()

                # If sk is None, then just assign the prepared
                # encrypted bit. Otherwise, recrypt before assigning.
                if int(bit) == 0:
                    if sk is not None:
                        lib_scarab.fhe_recrypt(encrypted_zero, self, sk)
                    assign_c_mpz_t(c, encrypted_zero)
                elif int(bit) == 1:
                    if sk is not None:
                        lib_scarab.fhe_recrypt(encrypted_one, self, sk)
                    assign_c_mpz_t(c, encrypted_one)
                else:
                    raise ValueError('Plaintext can only be 0 or 1.')

                encrypted_array[i] = c
            return encrypted_array
        else:
            c = make_c_mpz_t()
            lib_scarab.fhe_encrypt(c, self, int(plain))
            if sk is not None:
                lib_scarab.fhe_recrypt(c, self, sk)
            return EncryptedBit(self, c)

    def __str__(self):
        """Serialize public key to JSON string"""
        return serialize_c_fhe_pk_t(self._as_parameter_)

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
