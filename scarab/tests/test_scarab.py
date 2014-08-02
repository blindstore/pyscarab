"""Scarab wrapper unit tests"""

import json
import ctypes

from scarab import *

from scarab.loader import Library
from scarab.types import *

from nose.tools import *


lib_scarab = Library.load('scarab')


class TestTypes(object):

    """Test typedefs"""

    def test_sk_init(self):
        sk = c_fhe_sk_t()
        lib_scarab.fhe_sk_init(sk)
        lib_scarab.fhe_sk_clear(sk)

    def test_pk_init(self):
        pk = c_fhe_pk_t()
        lib_scarab.fhe_pk_init(pk)
        lib_scarab.fhe_pk_clear(pk)

    def test_mpz_compare(self):
        a = make_c_mpz_t()
        b = make_c_mpz_t()
        assert_true(compare_c_mpz_t(a, b) == 0)
        b = ctypes.c_ulong(50)
        assert_true(compare_c_mpz_t(a, b) != 0)

    def test_mpz_serialization(self):
        mpz = make_c_mpz_t()
        stringified = serialize_c_mpz_t(mpz)
        assert_equals(stringified, '0')

    def test_mpz_deserialization(self):
        pk, sk = generate_pair()
        mpz = pk.encrypt(1)
        stringified = serialize_c_mpz_t(mpz)
        mpz1 = deserialize_c_mpz_t(stringified)
        assert_true(compare_c_mpz_t(mpz, mpz1) == 0)

    def test_pk_serialization(self):
        pk, sk = generate_pair()
        stringified = serialize_c_fhe_pk_t(pk._as_parameter_)
        jsonified = json.loads(stringified)

    def test_pk_deserialization(self):
        array = [1, 1, 1, 0, 1, 0, 0, 1]
        pk, sk = generate_pair()
        stringified = serialize_c_fhe_pk_t(pk._as_parameter_)
        pk1 = deserialize_c_fhe_pk_t(stringified)
        encrypted_array = PublicKey(pk1).encrypt(array)
        decrypted_array = sk.decrypt(encrypted_array)
        assert_equals(decrypted_array, array)


class TestEncryptedArray(object):

    """EncryptedArray unit tests"""

    def setup(self):
        self.pk, self.sk = generate_pair()
        self.array = EncryptedArray(16, self.pk)

    def test_iteration(self):
        counter = 0
        for c in self.array:
            counter += 1
            assert_not_equals(c, None)
        assert_equals(counter, 16)

    def test_get(self):
        self.array[5]
        assert_raises(Exception, self.array, 16)

    def test_get(self):
        m = make_c_mpz_t()
        self.array[5] = m
        assert_true(compare_c_mpz_t(self.array[5], m) == 0)

    def test_len(self):
        assert_equals(len(self.array), 16)

    # def test_recrypt(self):
    #     old = list(self.array._array)
    #     self.array.recrypt()
    #     new = list(self.array._array)
    #     assert_not_equals(old, new)


class TestEncryption(object):

    """Test key generation and encryption"""

    def setup(self):
        self.pk, self.sk = generate_pair()

    def test_generate_pair(self):
        assert_true(compare_c_mpz_t(self.pk, make_c_mpz_t()) != 0)
        assert_true(compare_c_mpz_t(self.sk, make_c_mpz_t()) != 0)

    def test_bit_encryption(self):
        b = 0
        c = self.pk.encrypt(b)
        assert_true(isinstance(c, EncryptedBit))
        p = self.sk.decrypt(c)
        assert_equals(p, b)

    def test_array_encryption(self):
        m = [0, 0, 0, 0, 0, 0, 0, 0]
        c = self.pk.encrypt(m)
        p = self.sk.decrypt(c)
        assert_true(compare_c_mpz_t(c[0], make_c_mpz_t()) != 0)
        assert_equals(m, p)

        m = [1, 0, 1, 0, 1, 0, 1, 0]
        c = self.pk.encrypt(m)
        p = self.sk.decrypt(c)
        assert_true(compare_c_mpz_t(c[0], make_c_mpz_t()) != 0)
        assert_equals(m, p)

        m = [1, 1, 1, 1, 1, 1, 1, 1]
        c = self.pk.encrypt(m)
        p = self.sk.decrypt(c)
        assert_true(compare_c_mpz_t(c[0], make_c_mpz_t()) != 0)
        assert_equals(m, p)


class TestHomomorphicOperations(object):

    """Test homomorphic AND, XOR, +"""

    def setup(self):
        self.pk, self.sk = generate_pair()

    def test_array_xor(self):
        def check_result(a, b):
            ea = self.pk.encrypt(a)
            eb = self.pk.encrypt(b)
            r = self.sk.decrypt(ea ^ eb)
            c = list(map(lambda t: t[0] ^ t[1], zip(a, b)))
            print (a, b, c, r)
            assert_equals(r, c)
        pairs = [
            ([0, 0, 0, 0], [0, 0, 0, 0]),
            ([0, 0, 1, 1], [0, 0, 1, 1]),
            ([1, 1, 1, 1], [1, 1, 1, 1]),
        ]
        for a, b in pairs:
            check_result(a, b)

    def test_array_and(self):
        def check_result(a, b):
            ea = self.pk.encrypt(a)
            eb = self.pk.encrypt(b)
            r = self.sk.decrypt(ea & eb)
            c = list(map(lambda t: t[0] & t[1], zip(a, b)))
            print (a, b, c, r)
            assert_equals(r, c)
        pairs = [
            ([0, 0, 0, 0], [0, 0, 0, 0]),
            ([0, 0, 1, 1], [0, 0, 1, 1]),
            ([1, 1, 1, 1], [1, 1, 1, 1]),
        ]
        for a, b in pairs:
            check_result(a, b)

    def test_bit_xor(self):
        def check_result(a, b):
            ea = self.pk.encrypt(a)
            eb = self.pk.encrypt(b)
            r = self.sk.decrypt(ea ^ eb)
            c = a ^ b
            print (a, b, c, r)
            assert_equals(r, c)
        pairs = [
            (0, 0),
            (0, 1),
            (1, 0),
            (1, 1),
        ]
        for a, b in pairs:
            check_result(a, b)

    def test_bit_and(self):
        def check_result(a, b):
            ea = self.pk.encrypt(a)
            eb = self.pk.encrypt(b)
            r = self.sk.decrypt(ea & eb)
            c = a & b
            print (a, b, c, r)
            assert_equals(r, c)
        pairs = [
            (0, 0),
            (0, 1),
            (1, 0),
            (1, 1),
        ]
        for a, b in pairs:
            check_result(a, b)


class TestSerialization(object):

    def test_public_key_serialization(self):
        array = [1, 1, 1, 0, 1, 0, 0, 1]
        pk, sk = generate_pair()
        stringified = str(pk)
        pk1 = PublicKey(stringified)
        encrypted_array = pk1.encrypt(array)
        decrypted_array = sk.decrypt(encrypted_array)
        assert_equals(decrypted_array, array)

    def test_encrypted_bit_serialization(self):
        pk, sk = generate_pair()
        a = pk.encrypt(1)
        stringified = str(a)
        b = EncryptedBit(pk, stringified)
        one = sk.decrypt(b)
        assert_equals(one, 1)

    def test_encrypted_array_serialization(self):
        array = [1, 1, 1, 0, 1, 0, 0, 1]
        pk, sk = generate_pair()
        enc_array = pk.encrypt(array)
        stringified = str(enc_array)
        enc_array1 = EncryptedArray(len(array), pk, stringified)
        array1 = sk.decrypt(enc_array1)
        assert_equals(array, array1)


