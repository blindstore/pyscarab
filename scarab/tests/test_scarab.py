"""Scarab wrapper unit tests"""

import ctypes

from scarab import generate_pair, PublicKey, PrivateKey, EncryptedArray

from scarab.loader import Library
from scarab.types import c_mpz_t, c_fhe_sk_t, c_fhe_pk_t, \
                         make_c_mpz_t, compare_c_mpz_t

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

    def test_encryption(self):
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

    def test_xor(self):
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

    def test_and(self):
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

    # def test_add(self):
    #     def check_result(a, b, c):
    #         ea = self.pk.encrypt(a)
    #         eb = self.pk.encrypt(b)
    #         r = self.sk.decrypt(ea + eb)
    #         print (a, b, c, r)
    #         assert_equals(r, c)
    #     values = [
    #         ([0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]),
    #         ([0, 0, 1, 1], [0, 0, 1, 1], [0, 1, 1, 0]),
    #         ([1, 1, 1, 1], [1, 1, 1, 1], [1, 1, 1, 1, 0]),
    #     ]
    #     for a, b, c in values:
    #         check_result(a, b, c)