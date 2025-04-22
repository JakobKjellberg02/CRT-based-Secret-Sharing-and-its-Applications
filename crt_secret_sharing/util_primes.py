import math
from Crypto.Util.number import getPrime, isPrime, GCD

def pairwise_coprime(primes):
    if not all(isPrime(p) for p in primes):
        raise ValueError("Given integer is not prime.")
    return len(primes) == len(set(primes))

def primes_within_bitlength(primes, p_lambda):
    return all(p.bit_length() <= p_lambda for p in primes)

def generate_party_primes(n, p_0, p_lambda):
    primes = set()
    while len(primes) < n:
        prime = getPrime(p_lambda)
        if prime != p_0 and prime not in primes:
            primes.add(prime)
    return sorted(primes)

def generate_weighted_party_primes(p_0, weights, c):
    num_p = len(weights)
    p_i = [0] * num_p
    generated_primes = {p_0}

    for i, w in enumerate(weights):
        prime_length = max(8, math.ceil(c*w))
        while True:
            prime = getPrime(prime_length)
            if all(GCD(prime, p) == 1 for p in generated_primes):
                p_i[i] = prime
                generated_primes.add(prime)
                break
        
    if 0 in p_i:
        raise ValueError(f"Failed to generate unique primes")
    return p_i
