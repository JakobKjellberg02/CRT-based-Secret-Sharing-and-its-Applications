"""
Constructing Ideal Secret Sharing Schemes based on Chinese Remainder Theorem
https://eprint.iacr.org/2018/837.pdf

Based on Section 3 (Threshold Scheme based on CRT for Polynomial Ring over Finite Field)

"""
from sympy import Poly, gcd
from sympy.abc import x
import random
from share_reconstruction import *

def irreducible_poly_test(f, p):
    d = f.degree()

    h = Poly(x, x, modulus=p)
    for k in range(1, (d // 2) + 1):
        h = (h ** p).rem(f)
        if gcd(h - Poly(x, x, modulus=p), f) != 1:
            return False
    return True

def generation_algorithm_of_random_irreducible_polynomial(p: int, d_0, n: int, m_0):
    """
    Algorithm 2 (Generation Algorithm of Random Irreducible Polynomial)
    """
    irreducibles_polys = []
    while len(irreducibles_polys) < n:
        f_coeffs = [random.randint(0, p - 1) for _ in range(d_0)]
        f_coeffs.append(random.randint(1, p - 1))
        f = Poly(f_coeffs[::-1], x, modulus=p)
        
        if irreducible_poly_test(f, p):
            irreducibles_polys.append(f)
    return irreducibles_polys

def check_for_coprime(m_0, moduli):
    for i in range(len(moduli)):
        if gcd(m_0, moduli[i]).degree() > 0:
            return False
    return True

def check_degree_order(m_0, moduli):
    degrees = [m_0.degree()] + [m.degree() for m in moduli]
    return degrees == sorted(degrees)

def check_degree_constraint(m_0, moduli, t):
    degrees = [m.degree() for m in moduli]
    n = len(moduli)
    left_side = m_0.degree() + sum(degrees[n - t + 1 : n])
    right_side = sum(degrees[:t])
    return left_side <= right_side

def poly_satisfaction(m_0, moduli, t):
    if not check_for_coprime(m_0, moduli):
        print("Failed coprime check (6)")
        return False
    if not check_degree_order(m_0, moduli):
        print("Failed degree order check (7)")
        return False
    if not check_degree_constraint(m_0, moduli, t):
        print("Failed degree constraint check (8)")
        return False
    return True

def generate_secret(p, d_0, moduli, t):
    secret_coeffs = [random.randint(0, p - 1) for _ in range(d_0)]
    s = Poly(secret_coeffs, x, modulus=p)

    sum_di = sum([m.degree() for m in moduli[:t]])
    alpha_degree = sum_di - d_0 - 1
    alpha_degree = max(alpha_degree, 0)

    alpha_coeffs = secret_coeffs = [random.randint(0, p - 1) for _ in range(alpha_degree + 1)]
    alpha = Poly(alpha_coeffs, x, modulus=p)

    return s, alpha

def shares(s, alpha, m_0, moduli):
    f = s + alpha * m_0
    shares = [f % m for m in moduli]
    return f, shares

def scheme_setup(p: int, d_0: int, n : int) -> Poly:
    m_0 = Poly(x ** d_0, x, modulus = p)
    moduli = generation_algorithm_of_random_irreducible_polynomial(p, d_0, n, m_0)

    if not poly_satisfaction(m_0, moduli, t):
        raise ValueError("Polynomials do not satisfy the expressions")
    else:
        print("--- SUCCESSFUL CHECK FOR POLYS ---")

    return m_0, moduli

if __name__ == "__main__":
    """
    Subsection 3.1 (The Scheme)
    """
    # Parameters that will get initialized if ran as main script
    d_0 = 3        # Degree 
    p = 11         # Prime integer 
    threshold = (3,2)    # Threshold 
    n,t = threshold
    m_0, moduli = scheme_setup(p, d_0, n)
    print("m_0:", m_0)
    print("\nIrreducible polynomials (moduli):")
    for i, poly in enumerate(moduli):
        print(f"f_{i+1} = {poly}")
    
    s, alpha = generate_secret(p, d_0, moduli, t)
    print("\nSecret polynomial s(x):", s)
    print("Random polynomial α(x):", alpha)

    f, shares = shares(s, alpha, m_0, moduli)
    print("\nCombined polynomial f(x):", f)
    print("\nShares (s_i):")
    for i, share in enumerate(shares):
        print(f"s_{i+1}(x): {share}")
    
    # --- TEST ---
    reconstruction_index = [0,1]
    reconstruct_shares = [shares[i] for i in reconstruction_index]
    reconstruct_shares = [moduli[i] for i in reconstruction_index]

    reconstructed_the_secret = reconstruct_secret(shares, moduli, m_0, p)
    print("Reconstructed Secret:", reconstructed_the_secret)


