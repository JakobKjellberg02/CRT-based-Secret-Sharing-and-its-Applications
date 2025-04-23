import secrets
from math import prod, ceil
from typing import List, Optional
from Crypto.Util.number import getPrime, isPrime
from crt_secret_sharing.util_primes import generate_weighted_party_primes
from crt_secret_sharing.crt_ss import share_distribution, share_reconstruction
from crt_secret_sharing.bcolors import bcolors as bc

# --- Approx. of min. and max. ---

def approx_min_product_weights(min_weight : int, weights : List[int], p_i : List[int]) -> int:
    """
    Approximation of the minimum product of the weights

    Parameters
    ----------
        min_weight : int
            The minimum weight for an authroized set.
        weights : List[int]
            List of shareholder's weights.
        p_i : List[int]
            List of distinct coprime integers for each shareholder.

    Returns
    -------
        primes : int
            Product of primes.
    """
    sorted_pairs = sorted(zip(weights, p_i), key=lambda x: x[1])
    current_w = 0
    primes = []
    for w, p in sorted_pairs:
        current_w += w
        primes.append(p)
        if current_w >= min_weight:
            break
    if current_w < min_weight:
        print(f"Could not meet minimum weight")
    return prod(primes) if primes else 1

def approx_max_product_weights(max_weight : int, weights : List[int], p_i : List[int]) -> int:
    """
    Approximation of the maximum product of the weights

    Parameters
    ----------
        max_weight : int
            The maximum weight for approx.
        weights : List[int]
            List of shareholder's weights.
        p_i : List[int]
            List of distinct coprime integers for each shareholder.

    Returns
    -------
        primes : int
            Product of primes.
    """
    sorted_pairs = sorted(zip(weights, p_i), key=lambda x: x[1], reverse=True)
    current_w = 0
    primes = []
    for w, p in sorted_pairs:
        if current_w + w <= max_weight:
            current_w += w
            primes.append(p)
    return prod(primes) if primes else 1

# --- Computation of valid L ---

def compute_valid_L(P_min : int, P_max : int, p_0 : int, p_lambda : int) -> int:
    """
    Computing the valid L for weighted ramp secret sharing.

    Parameters
    ----------
        P_min : int
            Min. approx.
        P_max : int
            Max. approx.
        p_0 : int:
            Order of field F.
        p_lambda : int
            Security parameter of bit length.

    Returns
    -------
        upper_bound : int
            Largest possible L.
    """
    # Validate that P_min and P_max didn't mess up
    if P_min <= 0 or P_max <= 0:
        raise ValueError("P_min and P_max must be positive")
    
    # Security lower bound (leakage)
    lower_bound = P_max * (1 << p_lambda) + 1

    # Correctness upper bound
    upper_bound = P_min // p_0

    # Validate that the upper bound is larger than lower bound
    if lower_bound >= upper_bound:
        raise ValueError("Could not satisfy both correcntess and security for weighted.")
    return lower_bound

# --- Computation of gap ---

def compute_c(T : int, t : int, p_lambda : int) -> int:
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
        raise ValueError(f"The Reconstruction threshold ({T}) must be larger than Privacy threshold ({t}).")
    req_prod = 2 * p_lambda + 1 
    c = ceil(req_prod / gap)
    # c >= ceil((2 * p_lambda + 1) / (T - t))
    return max(1, c)

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

    """
    
    if len(weights) > n:
        raise ValueError(f"Entries of weight ({len(weights)}) should not exceed shareholders ({n})")
    if T <= t:
        raise ValueError(f"Privacy threshold ({t}) can not be higher than Reconstruction threshold ({T})")

    if not p_lambda >= 128:
        print(bc.WARNING + f"Bit-length is recommended to be at least 128." + bc.ENDC)
    print(bc.OKGREEN + f"Security parameter is ({p_lambda}) bit length.")
    
    if p_0 is None:
        p_0 = getPrime(p_lambda)
    elif not isPrime(p_0):
        raise ValueError(f"p_0 ({p_0}) has to be a prime.")
    print(bc.OKGREEN + f"Order of the field ({p_0}).")


    c = compute_c(T, t, p_lambda)
    p_i = generate_weighted_party_primes(p_0, weights, c)

    P_min = approx_min_product_weights(T, weights, p_i)
    P_max = approx_max_product_weights(t, weights, p_i)
    L = compute_valid_L(P_min, P_max, p_0, p_lambda)

    big_s, shares, p_0, p_i = share_distribution(p_lambda, n, T, small_s, p_0, p_i, L, True)
    return big_s, shares, p_0, p_i

# --- Main ---

if __name__ == "__main__":
    n = 5
    T = 25
    t = 10
    weights = [2,7,9,10,12]
    p_lambda = 128

    big_s, shares, p_0, p_i = weighted_setup(p_lambda, n, T, t, weights, 420420, None)
    
    shareholders = {0,3,4}
    session_weight = sum(weights[i] for i in shareholders)

    shares_subset = [shares[i] for i in shareholders]
    primes_subset = [p_i[i] for i in shareholders]
    
    print(f"Session weight ({session_weight})")
    print(f"Using participants {shareholders} for reconstruction.")

    reconstructed_secret = share_reconstruction(p_0, primes_subset, shares_subset)

    