import secrets
from math import prod
from typing import List, Optional
from crt_secret_sharing.util_primes import generate_party_primes, pairwise_coprime, primes_within_bitlength
from crt_secret_sharing.util_crt import modinv
from crt_secret_sharing.bcolors import bcolors as bc
from Crypto.Util.number import getPrime, isPrime

# --- Core functions for CRT-SS ---

def share_distribution(p_lambda: int, 
                       n : int, 
                       t : int,
                       small_s : int, 
                       p_0 : Optional[int], 
                       p_i : Optional[List[int]], 
                       cand_L : Optional[int]) -> tuple[int, List[int], int, List[int]]:
    """
    Setup scheme for Access Structure, Parameters and Share the secret.

    Parameters
    ----------
        p_lambda : int
            Security parameter of bit length.
        n : int
            Number of shareholders.
        t : int
            Reconstruction threshold.
        small_s : int 
            The secret integer from Field F_p0.
        p_0 : Optional[int]
            Optional argument for the order of field F.
        p_i : Optional[List[int]]
            Optional argument for List of distinct coprime integers for each shareholder.
        cand_L : Optional[int]
            Optional argument for The upper bound for masking.

    Returns
    -------
        big_s : int 
            Lifting of the secret(s) known as Lift(s).
        s_i : List[int]
            List(s_i) of the shareholder's secret.
        p_0 : int
            Order of field F.
        p_i : List[int]
            List of distinct coprime integers for each shareholder.

    """
    # Parameter for secret
    print(bc.OKGREEN + f"The secret ({small_s})." + bc.ENDC)

    # Recommended bit length
    if not p_lambda >= 128:
        print(bc.WARNING + f"Bit-length is recommended to be at least 128." + bc.ENDC)
    print(bc.OKGREEN + f"Security parameter is ({p_lambda}) bit length.")

    # Validate that threshold does not exceed shareholders
    if n < t:
        raise ValueError(f"The amount of shareholders ({n}) must not be less threshold ({t}).")
    print(bc.OKGREEN + f"Amount of shareholder ({n}) and threshold ({t})." + bc.ENDC)
    
    # Validation of order
    if p_0 is None:
        p_0 = getPrime(p_lambda)
    elif not isPrime(p_0):
        raise ValueError(f"p_0 ({p_0}) has to be a prime.")
    print(bc.OKGREEN + f"Order of the field ({p_0}).")

    # Validation of distinct coprimes
    if p_i is None:
        p_i = generate_party_primes(n, p_0, p_lambda)
    elif not pairwise_coprime(p_i + [p_0]) and primes_within_bitlength(p_i + [p_0], p_lambda) and len(p_i) > n:
        raise ValueError("The given primes were not pairwise coprime, were over bit length "
        "or more entries of then given amount of Shareholders")
    print(bc.OKGREEN + f"The distict primes ({p_i})." + bc.ENDC)
    
    # Correctness of scheme
    L = crt_correctness(p_0, p_i, t, cand_L) 
    print(bc.OKGREEN + f"The upper bound limit ({L})" + bc.ENDC)    

    # Uniformly distributed random integer
    u_L = secrets.randbelow(L) + 1    # Uniformly distributed over [L] using secrets
    print(bc.OKGREEN + f"Uniformly distributed random integer ({u_L})." + bc.ENDC)

    # Lifting of (s)
    big_s = small_s + p_0 * u_L       # S = s + p_0 * U_L
    print(bc.OKGREEN + f"The lifting of s ({big_s})." + bc.ENDC)

    # Distribute shares to shareholders
    s_i = [big_s % p for p in p_i]    # s_i = S mod p_i 
    print(bc.OKGREEN + f"The secret shares for the Shareholders ({s_i})." + bc.ENDC)
    return big_s, s_i, p_0, p_i

def share_reconstruction(p_0 : int, p_subset : List[int], shares_subset : List[int]) -> int:
    """
    Method for reconstructing an authorized set A of shareholders

    Parameters
    ----------
        p_0 : int 
            Order of the field F.
        p_subset : List[int] 
            List of primes for shareholders in set A.
        shares_subset : List[int]
            List of secrets for shareholders in set A.
    
    Returns
    -------
        secret : int 
            The secret integer from Field F_p0.
    """
    if not p_subset or not shares_subset:
        raise ValueError("Subsets for prime and shares can't be empty.")
    if len(p_subset) != len(shares_subset):
        raise ValueError("Subsets have to be an equal amount.")

    P = prod(p_subset)                             # Product of primes in the subset
    # Chinese Remainder Theorem
    # It loops through the set A and we calculate the Langrange Coefficient
    # Which also can be written as: lambda_i = Q * Q^(-1)
    # to be used for the reconstruction: lambda_i * s_i mod P
    result = 0                                     
    for s_i, p_i in zip(shares_subset, p_subset):  
        Q_i = P // p_i                             # Q = Prod_(j neq i) P_j
        try:
            inv_Q_i = modinv(Q_i, p_i)             # Inverse of Q modulo p_i
        except ValueError as e:
            raise ValueError(f"Failed modinv({Q_i}, {p_i}): {e}") from e
        result += s_i * Q_i * inv_Q_i             
    S = result % P                                 # Reconstruction of lift(s)
    secret = S % p_0                               # Reconstruction of secret
    print(bc.OKBLUE + f"The reconstructed secret ({secret})." + bc.ENDC)
    return secret

# --- Correctness and Security for unweighted CRT-SS ---

def crt_correctness(p_0 : int, p_i : List[int], threshold : int, big_L : Optional[int]):
    """
    Checks for correctness according to Theoreom 5 (p. 12).

    if 'L' is None, then it calculates the candidate that gurantees
    that the scheme is perfectly correct.
    
    if 'L' is Some, then it validates the candidate to check for
    correctness.

    Parameters
    ----------
        p_0 : int
            Order(p_0) of the field F.
        p_i : List[int]
            List(p_i) of distinct coprime integers for each shareholder.
        threshold : int
            Threshold for the minimum amount of shares for reconstruction.
        big_L : Optional[int]
            An optional argument for the upper limit(L).
            If 'big_L' is provided, it will be checked for correctness.
    
    Returns
    -------
        L_candidate : int
            The value of 'L' will be returned satisfying correctness.
    """

    # Validate the input
    # Will only satisfy correctness for an Authorized set A
    if not p_i or len(p_i) < threshold:
        raise ValueError(f"Not enough shareholders ({len(p_i)}) for threshold ({threshold}).")
    if threshold < 1:
        raise ValueError(f"Threshold was ({threshold}) but needs to larger than 1.")

    sorted_pi = sorted(p_i)
    P_min = prod(sorted_pi[:threshold])         # P_min is minimum product of primes for Authroized set A
                                                # meaning we sort from lowest to highest and taking the 
                                                # The product of first elements til threshold

    if big_L is None:
        big_L = (P_min // (p_0 + 1)) - 1  # Upper bound limit to satisfy correctness

    # Validate the candidate to see if it satisfies for correctness
    # (L + 1) * p_0 < P_min
    if (big_L + 1) * p_0 < P_min and big_L >= 1:
        print(bc.OKGREEN + "The scheme is perfectly correct according to Theoreom 5." + bc.ENDC)
        return big_L
    else:
        raise ValueError("The scheme does not satisfy for correctness.")

# --- Main ---

if __name__ == "__main__":
    """
    Basic test case for how to use unweighted CRT-SS

    Example:
    (3,2)-threshold with bit-length 128
    The given secret is '420420'

    It will reconstruct successfully given Authorized set A
    """
    big_s, shares, p_0, p_i = share_distribution(128, 3, 2, 420420, None, None, None)
    test_number = 2
    shares_subset = shares[:test_number]
    primes_subset = p_i[:test_number]
    secret = share_reconstruction(p_0, primes_subset, shares_subset)