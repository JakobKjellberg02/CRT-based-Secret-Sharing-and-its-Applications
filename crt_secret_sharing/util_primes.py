import secrets
from sympy import nextprime

def generate_prime(p_lambda):
    return nextprime(2 ** p_lambda)
    
def generate_party_primes(n, p_0, p_lambda):
    primes = set()
    min_val = 2 ** (p_lambda - 1)
    max_val = 2 ** p_lambda - 1
    while len(primes) < n:
        random_int = secrets.SystemRandom().randint(min_val, max_val)
        prime = nextprime(random_int)
        if prime != p_0 and prime not in primes:
            primes.add(prime)
    return sorted(primes)

def generate_weighted_party_primes(p_0, weights, c):
    primes = set()
    for w in weights:
        prime_length = max(c * w, 64)
        while True:
            random_int = secrets.SystemRandom().randint(2 ** (prime_length - 1), 2 ** prime_length - 1)
            prime = nextprime(random_int)
            if prime != p_0 and prime not in primes:
                primes.add(prime)
                break
    return sorted(primes)
