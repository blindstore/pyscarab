from functools import reduce

from scarab import generate_pair
import numpy as np

_ADD = lambda a, b: a + b
_MUL = lambda a, b: a * b
_AND = lambda a, b: a & b
_XOR = lambda a, b: a ^ b


def binary(num):
    """Binary representation of an integer as a list of 0, 1

    >>> binary(10)
    [1, 0, 1, 0]

    :param num:
    :return: the binary representation of num
    """
    return [int(b) for b in list(bin(num)[2:])]


def gamma(cq, ci, co):
    """
    Calculates the value of the gamma function, as described in PDF (paragraph 3.1.2)
    :param cq: cipher query
    :param ci: cipher index
    :param co: cipher one
    :return: the value of the gamma function
    """
    return reduce(_AND, [a ^ b ^ co for a, b in zip(cq, ci)])


def R(gammas, column, public_key):
    """
    Calculates the value of R() function, as described in PDF (paragraph 3.1.3)
    :param gammas: gammas
    :param column: column
    :param public_key: public key
    :return: the value of the R function
    """
    return reduce(_XOR, gammas[np.where(column == 1)], public_key.encrypt(0))

########
database = np.array([[1, 0, 0, 0, 0, 0, 0, 0],
                     [1, 1, 0, 0, 0, 0, 0, 0],
                     [1, 1, 1, 0, 0, 0, 0, 0]])
L = 8
########


def server_generate_response(cipher_query, pk):
    indices = [binary(x) for x in range(database.size // L)]
    cipher_indices = [pk.encrypt(index) for index in indices]
    cipher_one = pk.encrypt(1)
    gammas = np.array([gamma(cipher_query, cipherindex, cipher_one) for cipherindex in cipher_indices])

    return np.array([R(gammas, database[:, c], pk) for c in range(L)])


def client_perform_query(i):
    pk, sk = generate_pair()
    response = server_generate_response(pk.encrypt(binary(i)), pk)
    result = [sk.decrypt(r) for r in response]
    return result

########
########
########

if __name__ == '__main__':
    row = client_perform_query(0)
    print(row)