from sympy import Poly, invert
from sympy.abc import x

def crt_poly(remainders, moduli, p):
    M = Poly(1, x, modulus=p)
    for m in moduli:
        M *= m

    X = Poly(0, x, modulus=p)
    for i in range(len(moduli)):
        Mi = M // moduli[i]
        try:
            Mi_inverse = invert(Mi, moduli[i])
        except:
            raise ValueError("Modular inverse does not exist")
        term = Mi * Mi_inverse * remainders[i]
        X += term

    X = X % M
    return X

def reconstruct_secret(shares, moduli, m_0, p):
    X = crt_poly(shares, moduli, p)
    secret = X % m_0
    return secret
