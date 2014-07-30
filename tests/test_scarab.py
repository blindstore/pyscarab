"""Scarab wrapper unit tests"""

import scarab

from loader import ScarabLoader
from typedefs import c_mpz_t, c_fhe_sk_t, c_fhe_pk_t

from nose.tools import *


load_scarab = ScarabLoader()
scarab = load_scarab()


class TestTypedefs(object):

    def test_sk_init(self):
        sk = c_fhe_sk_t()
        scarab.fhe_sk_init(sk)

    def test_pk_init(self):
        pk = c_fhe_pk_t()
        scarab.fhe_pk_init(pk)


class TestKeys(object):

    """Test key generation and encryption"""

    def setup(self):
        self.pk, self.sk = scarab.generate_pair()

    def test_generate_pair(self):
        assert_not_equals(self.pk.raw, 0)
        assert_not_equals(self.sk.raw, 0)

    def test_encryption(self):
        m = [1, 0, 1, 0, 1, 0, 1, 0]
        c = self.pk.encrypt()
        p = self.sk.decrypt(c)
        assert_equals(m, p)