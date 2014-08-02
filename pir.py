from functools import reduce

import numpy as np

from scarab import generate_pair, EncryptedBit


def binary(num):
    """Binary representation of an integer as a list of 0, 1

    >>> binary(10)
    [1, 0, 1, 0]

    :param num:
    :return: the binary representation of num
    """
    return [int(b) for b in list(bin(num)[2:])]


if __name__ == '__main__':
    # Step 0: Keypair generation
    pk, sk = generate_pair()
    print('Keypair generated')

    database = np.array([[1, 0, 0, 0, 0, 0, 0, 0],
                         [1, 1, 0, 0, 0, 0, 0, 0],
                         [1, 1, 1, 0, 0, 0, 0, 0]])

    L = 8

    # Step 1: (client) Query generation
    query = binary(1)
    cipher_query = pk.encrypt(query)

    print('Query generated')

    # Step 2.1: (server) Gamma
    indices = [binary(0), binary(1), binary(2)]
    cipher_indices = [pk.encrypt(index) for index in indices]
    cipher_one = pk.encrypt(1)

    def gamma(cipher_query, cipher_index):
        result = pk.encrypt(1)
        for alpha, beta in zip(cipher_query, cipher_index):
            result &= alpha ^ beta ^ cipher_one
        assert isinstance(result, EncryptedBit)
        return result

    gammas = np.array([gamma(cipher_query, cipherindex) for cipherindex in cipher_indices])

    print('Gammas calculated')

    # Step 2.2: (server) Rs

    def R(gammas, column):
        return reduce(EncryptedBit.__xor__, gammas[np.where(column == 1)], pk.encrypt(0))

    Rs = np.array([R(gammas, database[:, c]) for c in range(L)])

    # Rs sent back to client

    result = [sk.decrypt(r) for r in Rs]
    print(result)