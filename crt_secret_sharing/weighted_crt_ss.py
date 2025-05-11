from math import ceil
from typing import List, Optional
from Crypto.Util.number import getPrime, isPrime
from crt_secret_sharing.util_primes import generate_weighted_party_primes
from crt_secret_sharing.crt_ss import share_distribution, share_reconstruction
from crt_secret_sharing.bcolors import bcolors as bc

# --- Efficient WRSS ---

def efficient_scaling(T : int, t : int, weights : List[int], p_lambda : int):
    """
    Computes the constant needed for the ramp setting to hold. 

    Parameters
    ----------
        T : int 
            Reconstruction threshold.
        t : int 
            Privacy threshold.
        p_lambda : int
            Security parameter of bit length.

    Returns
    -------
        c : int
            Constant c for gap.
    """
    gap = T - t 
    if gap <= 0:
        raise ValueError(f"Reconstruction threshold {T} must be bigger than Privacy threshold {t}.")
    c = ceil((2 * p_lambda + 1) / gap)

    scaled_weights = [c * w for w in weights]
    scaled_T = c * T
    scaled_t = c * t 

    return scaled_T, scaled_t, scaled_weights, c
    

# --- Weighted CRT-SS Setup ---

def weighted_setup(p_lambda: int, 
                       n : int,
                       T : int,
                       t : int,
                       weights: List[int],
                       small_s: int,
                       p_0 : Optional[int],
                       ):
    """
    Setup for WRSS using CRT-based Secret Sharing.

    Parameters
    ----------
        p_lambda : int
            Security parameter of bit length.
        n : int
            Number of shareholders.
        T : int
            Reconstruction threshold.
        t : int 
            Privacy threshold.
        weights : List[int]
            Weights for the shareholders.
        small_s : int 
            The secret integer from Field F_p0.
        p_0 : Optional[int]
            Optional argument for the order of field F.
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
        c : int
            c constant.

    """
    # Weights cannot exceed number of shareholders
    if len(weights) > n:
        raise ValueError(f"Entries of weight ({len(weights)}) should not exceed shareholders ({n})")
    
    # Privacy threshold cannot be bigger than Reconstruction threshold
    if T <= t:
        raise ValueError(f"Privacy threshold ({t}) can not be higher than Reconstruction threshold ({T})")
    
    # Corollary 1 for Efficient WRSS
    T, t, weights, c = efficient_scaling(T, t, weights, p_lambda)
    print(bc.OKGREEN + f"The constant c is {c}." + bc.ENDC)

    # Recommended bit length
    if not p_lambda >= 128:
        print(bc.WARNING + f"Bit-length is recommended to be at least 128." + bc.ENDC)
    print(bc.OKGREEN + f"Security parameter is ({p_lambda}) bit length." + bc.ENDC)
    
    # Validation of order
    if p_0 is None:
        p_0 = getPrime(p_lambda)
    elif not isPrime(p_0):
        raise ValueError(f"p_0 ({p_0}) has to be a prime.")
    print(bc.OKGREEN + f"Order of the field ({p_0})." + bc.ENDC)

    # Generate party primes with weights
    p_i = generate_weighted_party_primes(p_0, weights)

    # Theorem 6 (p. 13)
    L = (2 ** (t + p_lambda))

    # Make share distribtution from crt_ss
    big_s, shares, p_0, p_i = share_distribution(p_lambda, n, T, small_s, p_0, p_i, L, True)
    return big_s, shares, p_0, p_i, c

# --- Main ---

if __name__ == "__main__":
    """
    Basic test case for how to use WRSS

    Example:
    Privacy threshold of t 15 and Reconstruction threshold of T 25 with bit length 128
    The given secret is '420420'

    It will reconstruct successfully given Authorized set A
    """
    n = 5
    T = 25
    t = 15
    weights = [3,7,9,10,12]
    p_lambda = 128

    big_s, shares, p_0, p_i, c = weighted_setup(p_lambda, n, T, t, weights, 420420, None)
    
    shareholders = {0,3,4}
    session_weight = sum(weights[i] for i in shareholders)

    shares_subset = [shares[i] for i in shareholders]
    primes_subset = [p_i[i] for i in shareholders]
    
    print(f"Session weight ({session_weight})")
    print(f"Using participants {shareholders} for reconstruction.")

    reconstructed_secret = share_reconstruction(p_0, primes_subset, shares_subset)

    