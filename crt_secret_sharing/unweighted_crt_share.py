from random import randint as randomNumber
from math import prod
from crt_secret_sharing.util_primes import generate_party_primes, generate_prime
from crt_secret_sharing.util_crt import modinv

def share_distribution(small_s, p_0, p_i, L):
    u_L = randomNumber(1, L)
    big_s = small_s + p_0 * u_L
    p_i = [big_s % p for p in p_i]
    return big_s, p_i

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

if __name__ == "__main__":
    threshold = (5,3)    
    n,t = threshold
    small_s = 420420
    p_lambda = 64
    p_0 = generate_prime(p_lambda)
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