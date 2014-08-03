"""Scarab wrapper unit tests"""

import json
import copy
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

class TestEncryptedBit(object):

    """EncryptedBit unit tests"""

    def setup(self):
        self.pk, self.sk = generate_pair()

    def test_recryption_ciphertext(self):
        """Test that the recrypted ciphertext is different
        when using recrypt function in EncryptedBit class."""
        for plain in [0, 1]:
            ciphertext = self.pk.encrypt(plain)
            c = make_c_mpz_t()
            assign_c_mpz_t(c, ciphertext._as_parameter_)
            ciphertext_copy = EncryptedBit(self.pk, c)
            ciphertext.recrypt(self.sk)
            assert_true(compare_c_mpz_t(ciphertext._as_parameter_,
                                        ciphertext_copy._as_parameter_) != 0)

    def test_recryption_plaintext(self):
        """Test that the recrypted ciphertext decrypts to
        the same plaintext when using recrypt function in
        EncryptedBit class.
        """
        for plain in [0, 1]:
            ciphertext = self.pk.encrypt(plain)
            ciphertext.recrypt(self.sk)
            decrypted = self.sk.decrypt(ciphertext)
            assert_equals(plain, decrypted)

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

    def test_recryption_ciphertext(self):
        """Test that the recrypted ciphertext is different
        when using recrypt function in EncryptedArray class."""
        encrypted_array = self.pk.encrypt([0, 1, 0, 0, 1, 0, 0, 1])
        old_array = [make_c_mpz_t() for i in range(8)]
        for a, b in zip(old_array, encrypted_array._array):
            assign_c_mpz_t(a, b)
        encrypted_array.recrypt(self.sk)
        for a, b in zip(old_array, encrypted_array._array):
            assert_true(compare_c_mpz_t(a, b) != 0)

    def test_recryption_plaintext(self):
        """Test that the recrypted ciphertext decrypts to
        the same plaintext when using recrypt function in
        EncryptedArray class.
        """
        encrypted_array = self.pk.encrypt([0, 1, 0, 0, 1, 0, 0, 1])
        encrypted_array.recrypt(self.sk)
        decrypted_array = self.sk.decrypt(encrypted_array)
        assert_equals([0, 1, 0, 0, 1, 0, 0, 1], decrypted_array)


class TestEncryption(object):

    """Test key generation and encryption"""

    def setup(self):
        self.pk, self.sk = generate_pair()

    def test_generate_pair(self):
        assert_true(compare_c_mpz_t(self.pk, make_c_mpz_t()) != 0)
        assert_true(compare_c_mpz_t(self.sk, make_c_mpz_t()) != 0)

    def test_bit_encryption(self):
        """Check that decryption of an encrypted bit again leads
        to the plaintext.
        """
        for plain in [0, 1]:
            c = self.pk.encrypt(plain)
            assert_true(isinstance(c, EncryptedBit))
            p = self.sk.decrypt(c)
            assert_equals(p, plain)

    @nottest
    def test_bit_encryption_determinism(self):
        """Check that encryption of the same plaintext over and over
        again leads to the same ciphertext.

        FIXME: Test on EncryptedArray
        """
        for plain in [0, 1]:
            c = self.pk.encrypt(plain)
            for i in range(100):
                same = self.pk.encrypt(plain)
                assert_true(compare_c_mpz_t(
                    c._as_parameter_, same._as_parameter_) == 0)

    def test_bit_recryption(self):
        """Check that when passing the secret key to PublicKey.encrypt()
        the encryption is done using recrypt and thus the same as when
        first encrypt without passing the secret key and then calling
        recrypt function on the EncryptedBit object.
        """
        for plain in [0, 1]:
            without_recrypt = self.pk.encrypt(plain)
            without_recrypt.recrypt(self.sk)
            with_recrypt = self.pk.encrypt(plain, self.sk)
            assert_true(compare_c_mpz_t(without_recrypt._as_parameter_,
                with_recrypt._as_parameter_) == 0)

    def test_array_encryption(self):
        """Check that decryption of an encrypted array again leads
        to the plaintext.
        """
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

    def test_array_recryption(self):
        """Check that when passing the secret key to PublicKey.encrypt()
        the encryption is done using recrypt and thus different from the
        one done without passing the secret key. As EncryptedArray.recrypt()
        recrypts each bit independently, this will be not the same.
        """
        m = [1, 0, 1, 0, 1, 0, 1, 0]
        without_recrypt = self.pk.encrypt(m)
        with_recrypt = self.pk.encrypt(m, self.sk)
        for a, b in zip(without_recrypt._array, with_recrypt._array):
            assert_true(compare_c_mpz_t(a, b) != 0)

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


