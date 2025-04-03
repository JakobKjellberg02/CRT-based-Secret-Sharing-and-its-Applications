import math
import secrets
from math import prod
from crt_secret_sharing.util_primes import generate_weighted_party_primes
from crt_secret_sharing.util_crt import modinv
from Crypto.Util.number import getPrime

def share_distribution(small_s, p_0, p_i, L):
    u_L = secrets.randbelow(L)
    big_s = small_s + p_0 * u_L
    shares = [big_s % p for p in p_i]
    return big_s, shares

def share_reconstruction(p_0, p_subset, shares_subset):
    P = prod(p_subset)
    result = 0
    for s_i, p_i in zip(shares_subset, p_subset):
        Q_i = P // p_i
        inv_Q_i = modinv(Q_i, p_i)
        result += s_i * Q_i * inv_Q_i
    S = result % P
    secret = S % p_0
    return secret

def approx_min_product_weights(min_weight, weights, p_i):
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

def approx_max_product_weights(max_weight, weights, p_i):
    sorted_pairs = sorted(zip(weights, p_i), key=lambda x: x[1], reverse=True)
    current_w = 0
    primes = []
    for w, p in sorted_pairs:
        if current_w + w <= max_weight:
            current_w += w
            primes.append(p)
    return prod(primes) if primes else 1

def compute_valid_L(P_min, P_max, p_0, p_lambda):
    if P_min <= 0 or P_max <= 0:
        raise ValueError("P_min and P_max must be positive")
    lower_bound = P_max * (1 << p_lambda) + 1
    upper_bound = P_min // p_0

    if lower_bound >= upper_bound:
        raise ValueError("SOMETHING WENT REALLY WRONG")
    return lower_bound

def compute_c(T, t, p_lambda):
    gap = T - t
    if gap <= 0:
        raise ValueError("T must be greater than t")
    req_prod = 2 * p_lambda + 1 
    c = math.ceil(req_prod / gap)
    c = max(1, c)
    return c

def WRSS_setup(p_0, small_s, weights, T, t, p_lambda):
    c = compute_c(T, t, p_lambda)

    p_i = generate_weighted_party_primes(p_0, weights, c)

    P_min = approx_min_product_weights(T, weights, p_i)
    P_max = approx_max_product_weights(t, weights, p_i)
    L = compute_valid_L(P_min, P_max, p_0, p_lambda)

    big_s, shares = share_distribution(small_s, p_0, p_i, L)
    return big_s, shares, p_i


if __name__ == "__main__":
    n = 5
    T = 25
    t = 10
    weights = [3,7,9,10,12]
    p_lambda = 64

    p_0 = getPrime(p_lambda)
    small_s = secrets.randbelow(p_0)

    big_s, shares, p_i = WRSS_setup(p_0, small_s, weights, T, t, p_lambda)

    print("p_0", p_0)
    print("p_i", p_i)
    print("Secret:", small_s)
    print("Lifted S:", big_s)
    print("Shares:", shares)
    print("Weights:", weights)

    test_number = 4
    shares_subset = shares[:test_number]
    primes_subset = p_i[:test_number]
    print(f"Using first {test_number} shares and primes for reconstruction.")
    reconstructed_secret = share_reconstruction(p_0, primes_subset, shares_subset)
    print("Reconstructed secret:", reconstructed_secret)
    