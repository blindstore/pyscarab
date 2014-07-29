"""Scarab wrapper unit tests"""

import scarab

from nose.tools import *


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