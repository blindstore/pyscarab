"""Type definitions for `libscarab` types.h and GMP"""

from ctypes import POINTER, Structure, \
    c_ulonglong, c_int

import predefs


class _c__mpz_struct(Structure):

    """mpz_struct (GMP Integer) definition"""

    _fields_ = [
        ('_mp_alloc',   c_int),
        ('_mp_size',    c_int),
        ('_mp_d',       POINTER(c_ulonglong))] # might be ulong / uint

# mpz_t definition
c_mpz_t = _c__mpz_struct * 1


class _c__fhe_pk(Structure):

    """_fhe_pk (public key) definition"""

    _fields_ = [
        ('p',     c_mpz_t),
        ('alpha', c_mpz_t),
        ('c',     c_mpz_t * predefs.S1),
        ('B',     c_mpz_t * predefs.S1)]


# fhe_pk_t definition
c_fhe_pk_t = _c__fhe_pk * 1


class _c__fhe_sk(Structure):

    """_fhe_sk (private key) definition"""

    _fields_ = [
        ('p', c_mpz_t),
        ('B', c_mpz_t)]


# fhe_sk_t definition
c_fhe_sk_t = _c__fhe_sk * 1