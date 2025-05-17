from math import ceil
from sympy import prevprime
from secrets import SystemRandom
from Crypto.Util.number import getPrime, isPrime
from crt_secret_sharing.util_crt import gcd

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

def generate_weighted_party_primes(p_0, weights):
    num_p = len(weights)
    p_i = [0] * num_p
    generated_primes = {p_0}
    cryptogen = SystemRandom()

    for i, w in enumerate(weights):
        upper_bound = 2 ** w
        try:
            lower_bound = ceil(upper_bound * num_p // (num_p + 1))
        except OverflowError:
            raise ValueError("Constant c is way too big causing overflow error. " \
            "Gap between the thresholds needs to be wider")
        while True:
            random_cand = cryptogen.randrange(lower_bound, upper_bound)
            candidate = prevprime(random_cand)
            if isPrime(candidate) and all(gcd(candidate, p) == 1 for p in generated_primes):
                if candidate >= lower_bound:
                    p_i[i] = candidate
                    generated_primes.add(candidate)
                    break
    if 0 in p_i:
        raise ValueError(f"Failed to generate unique primes")
    return p_i
