from random import randint as randomNumber
from sympy import nextprime

def generate_prime(p_lambda):
    return nextprime(2 ** p_lambda)
    
def generate_party_primes(n, p_0, p_lambda):
    primes = set()
    min_val = 2 ** (p_lambda - 1)
    max_val = 2 ** p_lambda - 1
    while len(primes) < n:
        random_int = randomNumber(min_val, max_val)
        prime = nextprime(random_int)
        if prime != p_0 and prime not in primes:
            primes.add(prime)
    return sorted(primes)
