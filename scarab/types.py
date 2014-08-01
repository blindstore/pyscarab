"""Some low-level type definitions for `libscarab` and `GMP`"""

from ctypes import POINTER, Structure, \
    c_ulonglong, c_int

from .loader import Library
from .predefs import *


lib_gmp = Library.load('gmp')
lib_scarab = Library.load('scarab')


class _c__mpz_struct(Structure):

    """mpz_struct (GMP Integer) definition"""

    _fields_ = [
        ('_mp_alloc',   c_int),
        ('_mp_size',    c_int),
        ('_mp_d',       POINTER(c_ulonglong))] # might be ulong / uint

# mpz_t definition
c_mpz_t = _c__mpz_struct * 1


def make_c_mpz_t():
    """Construct an mpz_t instance"""
    c = c_mpz_t()
    lib_gmp.__gmpz_init(c)
    return c


# mpz_t destructor
clear_c_mpz_t = lib_gmp.__gmpz_clear


class _c__fhe_pk(Structure):

    """_fhe_pk (public key) definition"""

    _fields_ = [
        ('p',     c_mpz_t),
        ('alpha', c_mpz_t),
        ('c',     c_mpz_t * S1),
        ('B',     c_mpz_t * S1)]


# fhe_pk_t definition
c_fhe_pk_t = _c__fhe_pk * 1


def make_c_fhe_pk_t():
    """Construct an fhe_pk_t instance"""
    pk = c_fhe_pk_t()
    lib_scarab.fhe_pk_init(pk)
    return pk


# fhe_pk_t destructor
clear_c_fhe_pk_t = lib_scarab.fhe_pk_clear


class _c__fhe_sk(Structure):

    """_fhe_sk (private key) definition"""

    _fields_ = [
        ('p', c_mpz_t),
        ('B', c_mpz_t)]


# fhe_sk_t definition
c_fhe_sk_t = _c__fhe_sk * 1


def make_c_fhe_sk_t():
    """Construct an fhe_sk_t instance"""
    sk = c_fhe_sk_t()
    lib_scarab.fhe_sk_init(sk)
    return sk


# fhe_sk_t destructor
clear_c_fhe_sk_t = lib_scarab.fhe_sk_clear