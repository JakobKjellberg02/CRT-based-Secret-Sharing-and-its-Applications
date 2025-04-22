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
            The minimum weight for approx.
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
    Work in progress for weighted but computation should be looked at for both schemes.

    Parameters
    ----------
        P_min : int
            min. approx.

    Returns
    -------
        primes : int
            Product of primes.
    """
    if P_min <= 0 or P_max <= 0:
        raise ValueError("P_min and P_max must be positive")
    lower_bound = P_max * (1 << p_lambda) + 1
    upper_bound = P_min // p_0

    if lower_bound >= upper_bound:
        raise ValueError("SOMETHING WENT REALLY WRONG")
    return lower_bound

# --- Computation of gap ---

def compute_c(T : int, t : int, p_lambda : int) -> int:
    """
    Computes the gap between the thresholds for Ramp setting

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
    c = max(1, c)
    return c

# --- Weighted CRT-SS Setup ---

def weighted_setup(p_lambda: int, 
                       n : int,
                       T : int,
                       t : int,
                       weights: List[int],
                       small_s: int,
                       p_0 : Optional[int],
                       ):
    
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

    big_s, shares, p_0, p_i = share_distribution(128, n, T, small_s, p_0, p_i, L, True)
    return big_s, shares, p_0, p_i

# --- Main ---

if __name__ == "__main__":
    n = 5
    T = 25
    t = 10
    weights = [3,7,9,10,12]
    p_lambda = 16

    big_s, shares, p_0, p_i = weighted_setup(128, n, T, t, weights, 420420, None)
    
    test_number = 3
    shares_subset = shares[:test_number]
    primes_subset = p_i[:test_number]
    print(f"Using first {test_number} shares and primes for reconstruction.")
    reconstructed_secret = share_reconstruction(p_0, primes_subset, shares_subset)

    