from functools import reduce

import numpy as np

from scarab import generate_pair, EncryptedBit


def binary(num):
    return list(bin(10)[2:])


if __name__ == '__main__':
    # Step 0: Keypair generation
    pk, sk = generate_pair()
    print ('Keypair generated')

    database = np.array([[1, 0, 0, 0, 0, 0, 0, 0],
                         [1, 1, 0, 0, 0, 0, 0, 0],
                         [1, 1, 1, 0, 0, 0, 0, 0]])

    L = 8

    # Step 1: (client) Query generation
    query = binary(0)
    cipherquery = pk.encrypt(query)

    print ('Query generated')

    # Step 2.1: (server) Gamma
    indices = [binary(0), binary(1), binary(2)]
    cipherindices = [pk.encrypt(index) for index in indices]
    cipherone = pk.encrypt(1)

    def gamma(cipherquery, cipherindex):
        result = pk.encrypt(1)
        for alpha, beta in zip(cipherquery, cipherindex):
            result &= alpha ^ beta ^ cipherone
        assert isinstance(result, EncryptedBit)
        return result

    gammas = np.array(
        [gamma(cipherquery, cipherindex) for cipherindex in cipherindices])

    print ('Gammas calculated')

    # Step 2.2: (server) Rs

    def R(gammas, column):
        return reduce(EncryptedBit.__add__, gammas[np.where(column==1)], pk.encrypt(0))

    Rs = np.array([R(gammas, database[:,c]) for c in range(L)])

    result = [sk.decrypt(r) for r in Rs]
    print (result)