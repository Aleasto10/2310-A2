import sympy
import random
import config

LOW_PRIME = config.LOW_PRIME
HIGH_PRIME = config.HIGH_PRIME

def power(base, exponent, m):
    res = 1
    base = base % m
    while exponent > 0:
        if exponent & 1:
            res = (res * base) % m
        base = (base * base) % m
        exponent = exponent // 2
    return res

def modInverse(e, phi):
    for d in range(2, phi):
        if(e*d) % phi == 1:
            return d
    return -1

def extended_euclidean_algorithm(a, b):
    """
    extended_euclidean_algorithm(a, b)

    The result is the largest common divisor for a and b.

    :param a: integer number
    :param b: integer number
    :return:  the largest common divisor for a and b
    """

    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_euclidean_algorithm(b % a, a)
        return g, x - (b // a) * y, y

def modular_inverse(e, t):
    """
    modular_inverse(e, t)

    Counts modular multiplicative inverse for e and t.

    :param e: in this case e is a public key exponent
    :param t: and t is an Euler function
    :return:  the result of modular multiplicative inverse for e and t
    """

    g, x, y = extended_euclidean_algorithm(e, t)

    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % t



def generateKeys(low=LOW_PRIME, high=HIGH_PRIME):
    
    p = sympy.randprime(low,high)
    q = sympy.randprime(low,high)
    print(f"P, Q: {p}, {q}")

    n = p * q
    phi = (p-1) * (q-1)

    e = 0
    pos_e = []
    for e in range(2,phi):
        if gcd(e,phi) == 1:
            pos_e.append(e)
    e = pos_e[random.randint(0,len(pos_e)-1)]

    e = pos_e[0]

    d = modular_inverse(e, phi)

    return e,d,n

def gcd(a,b):
    while b != 0:
        a,b = b, a%b
    return a

def encrypt(m,e,n):
    return power(m,e,n)

def decrypt(c,d,n):
    if not isinstance(c, int):
        raise TypeError("RSA_l.decrypt expects integer ciphertext; convert bytes to int before calling.")
    return power(c,d,n)

if __name__ == "__main__":

    e,d,n = generateKeys()

    print(f'Public Key (e,n): ({e}, {n})')
    print(f"Private Key (d,n): ({d}, {n})")

    M = random.randint(1000,10000)

    print(f"Original message: {M}")

    C = encrypt(M,e,n)
    print(f"Encrypted message: {C}")

    decrypted = decrypt(C,d,n)
    print(f"Decrypted message: {decrypted}")