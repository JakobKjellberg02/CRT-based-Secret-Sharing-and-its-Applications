from random import randint as randomNumber
from crt_secret_sharing.util_primes import generate_prime
from crt_secret_sharing.weighted_crt_share import generate_weighted_party_primes, approx_max_product_weights, approx_min_product_weights, compute_random_L, share_distribution

def setup(p):
    g = randomNumber(2, p-1)
    s = randomNumber(1, p-1)
    h = pow(g, s, p)
    return g, s, h

def encryption():
    r = randomNumber(1, p-1)
    c1 = pow(g, r, p)
    sd = randomNumber(1, p-1)
    

if __name__ == "__main__":
    n = 5
    T = 19
    t = 12
    weights = [3,7,9,10,12]
    p_lambda = 64

    c = max(1, p_lambda // (T - t + 1))
    p_0 = generate_prime(p_lambda)
    g, s, h = setup(p_0, p_lambda)
    p_i = generate_weighted_party_primes(p_0, weights, c)

    P_min = approx_min_product_weights(T, weights, p_i)
    P_max = approx_max_product_weights(t, weights, p_i)
    L = compute_random_L(P_min, P_max, p_0, p_lambda)
    
    big_s, shares = share_distribution(s, p_0, p_i, L)
    print("\nWeighted CRT Secret Sharing:")
    print("p_0 =", p_0)
    print("p_i =", p_i)
    print("Secret key s =", s)
    print("Lifted secret S =", big_s)
    print("Shares =", shares)
    print("Weights =", weights)

