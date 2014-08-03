"""Some low-level type definitions for `libscarab` and `GMP`"""

import json

from ctypes import POINTER, Structure, \
    c_ulong, c_ulonglong, c_int, c_char_p, string_at

from .loader import Library
from .predefs import *


lib_gmp = Library.load('gmp')
lib_scarab = Library.load('scarab')
libc = Library.load('libc')


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

# mpz_t assignment
assign_c_mpz_t = lib_gmp.__gmpz_set

def compare_c_mpz_t(a, b):
    """Compare mpz_t"""
    if isinstance(b, c_ulong):
        return lib_gmp.__gmpz_cmp_ui(a, b)
    elif isinstance(b, c_mpz_t):
        return lib_gmp.__gmpz_cmp(a, b)
    else:
        raise TypeError('Unknown `b` type')


base = 62


def serialize_c_mpz_t(mpz):
    """
    Serialize mpz_t

    :type mpz: c_mpz_t
    :rtype   : str
    """
    c_str = lib_gmp.__gmpz_get_str(None, base, mpz)
    result = string_at(c_str).decode('ascii')
    libc.free(c_str)
    return result

def deserialize_c_mpz_t(serialized_mpz):
    """
    Deserialize mpz_t

    :type serialized_mpz: str
    :rtype              : c_mpz_t
    """
    c_str = c_char_p(serialized_mpz.encode('ascii'))
    result = make_c_mpz_t()
    flag = lib_gmp.__gmpz_set_str(result, c_str, base)
    assert flag == 0
    return result


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

def serialize_c_fhe_pk_t(pk):
    """
    Serialize c_fhe_pk_t

    :type pk: c_fhe_pk_t
    :returns: json dump of list of strings
    """
    result = {
        'p'    : serialize_c_mpz_t(pk[0].p),
        'alpha': serialize_c_mpz_t(pk[0].alpha),
        'c'    : [serialize_c_mpz_t(c_elem) for c_elem in pk[0].c],
        'B'    : [serialize_c_mpz_t(B_elem) for B_elem in pk[0].B]
    }
    return json.dumps(result)

def deserialize_c_fhe_pk_t(serialized_pk):
    """
    Deserialize fhe_pk_t

    :type serialized_pk: str
    :rtype             : fhe_pk_t
    """
    jsonified = json.loads(serialized_pk)
    result = make_c_fhe_pk_t()

    result[0].p = deserialize_c_mpz_t(jsonified['p'])
    result[0].alpha = deserialize_c_mpz_t(jsonified['alpha'])

    assert S1 == len(jsonified['c'])
    assert S1 == len(jsonified['B'])

    result[0].c = (c_mpz_t * S1)(*[deserialize_c_mpz_t(c_elem) for c_elem in jsonified['c']])
    result[0].B = (c_mpz_t * S1)(*[deserialize_c_mpz_t(B_elem) for B_elem in jsonified['B']])

    return result


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