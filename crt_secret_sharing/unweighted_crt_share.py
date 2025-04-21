import secrets
from math import prod
from crt_secret_sharing.util_primes import generate_party_primes
from crt_secret_sharing.util_crt import modinv
from Crypto.Util.number import getPrime

def share_distribution(small_s : int, p_0 : int, p_i: list, L: int):
    """
    Method for sharing the secret betweeen the shareholders.

    Parameters
    ----------
        small_s : int 
            The secret(s) integer from Field F_p0.
        p_0 : int
            Order(p_0) of the field F.
        p_i : list 
            List(p_i) of distinct coprime integers for each shareholder.
        L : int 
            The upper bound(L) for masking.

    Returns
    -------
        big_s : int 
            Lifting of the secret(s) known as Lift(s)
        s_i : list 
            List(s_i) of the shareholder's secret
    """
    u_L = secrets.randbelow(L) + 1    # Uniformly distributed over [L] using secrets
    big_s = small_s + p_0 * u_L       # S = s + p_0 * U_L
    s_i = [big_s % p for p in p_i]    # s_i = S mod p_i 
    return big_s, s_i

def share_reconstruction(p_0 : int, p_subset : list, shares_subset : list):
    """
    Method for reconstructing an authorized set A of shareholders

    Parameters
    ----------
        p_0 : int 
            Order(p_0) of the field F.
        p_subset : list 
            List(p_subset) of primes for shareholders in set A
        shares_subset : list 
            List(shares_subset) of secrets for shareholders in set A
    
    Returns
    -------
        secret : int 
            The secret(s) integer from Field F_p0
    """
    P = prod(p_subset)                             # Product of primes in the subset
    # Chinese Remainder Theorem
    # It loops through the set A and we calculate the Langrange Coefficient
    # Which also can be written as: lambda_i = Q * Q^(-1)
    # to be used for the reconstruction: lambda_i * s_i mod P
    result = 0                                     
    for s_i, p_i in zip(shares_subset, p_subset):  
        Q_i = P // p_i                             # Q = Prod_(j neq i) P_j
        inv_Q_i = modinv(Q_i, p_i)                 # Inverse of Q modulo p_i
        result += s_i * Q_i * inv_Q_i             
    S = result % P                                 # Reconstruction of lift(s)
    secret = S % p_0                               # Reconstruction of secret
    return secret

if __name__ == "__main__":
    """
    Basic test case for how to use unweighted CRT-SS
    """
    threshold = (5,3)    
    n,t = threshold
    small_s = 420420
    p_lambda = 64
    p_0 = getPrime(p_lambda)
    p_i = generate_party_primes(n, p_0, p_lambda)

    P_min = prod(sorted(p_i)[:t])
    L = (P_min // (p_0 + 1)) - 1 

    big_s, shares = share_distribution(small_s, p_0, p_i, L)
    print("Secret:", small_s)
    print("Lifted S:", big_s)
    print("Shares:", shares)
    
    test_number = 3
    shares_subset = shares[:test_number]
    primes_subset = p_i[:test_number]
    print(f"Using first {test_number} shares and primes for reconstruction.")
    reconstructed_secret = share_reconstruction(p_0, primes_subset, shares_subset)
    print("Reconstructed secret:", reconstructed_secret)