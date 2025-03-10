"""
Constructing Ideal Secret Sharing Schemes based on Chinese Remainder Theorem
https://eprint.iacr.org/2018/837.pdf

Based on Section 3 (Threshold Scheme based on CRT for Polynomial Ring over Finite Field)

"""
from sympy import Poly

def generation_algorithm_of_random_irreducible_polynomial(p: int, d_0, n: int):
    """
    Algorithm 2 (Generation Algorithm of Random Irreducible Polynomial)
    """
    irreducibles_polys = []
    while len(irreducibles_polys) < n:
        f_poly = random_poly(p, d_0)
        if test_poly_is_irreducible(f_poly):
            irreducibles_polys.append(f_poly)
            


def scheme_setup(p: int, d_0: int, threshold : tuple[int, int]) -> list:
    n, t  = threshold
    m_0 = Poly(x ** d_0, x, modulus = p)
    moduli = generation_algorithm_of_random_irreducible_polynomial(d_0)

if __name__ == "__main__":
    """
    Subsection 3.1 (The Scheme)
    """
    # Parameters that will get initialized if ran as main script
    d_0 = 1        # Degree 
    p = 11         # Prime integer 
    threshold = 3,2    # Threshold 


