from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
from crt_secret_sharing.util_primes import generate_prime
from crt_secret_sharing.weighted_crt_share import WRSS_setup

def universal_hashing(x):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str(x).encode())
    return int.from_bytes(digest.finalize(), 'big')

def randomness_extractor(s, X, p):
    hkdfsha256 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=s.to_bytes(32, 'big')
    )
    return int.from_bytes(hkdfsha256.derive(str(X).encode()),'big') % p


#def encryption():
    F_p = generate_prime(randomNumber(2 ** (p_lambda - 1), 2 ** p_lambda - 1))
    r = randomNumber(1, F_p-1)
    c1 = pow(g, r, p)
    sd = randomNumber(1, F_p1)
    seed = randomNumber(1, p-1)
    sd_extract = extractor(seed, sd, p)
    c2 = (m * sd_extract) % p
    H_sd = randomNumber(sd)
    return (c1, c2, seed, H_sd), r
    

if __name__ == "__main__":
    T = 19
    t = 12
    weights = [3,7,9,10,12]
    p_lambda = 256

    p_0 = generate_prime(p_lambda)
    small_s = secrets.randbelow(p_0)

    big_s, shares, p_0, p_i = WRSS_setup(p_0, small_s, weights, T, t, p_lambda)

    sd = secrets.SystemRandom.getrandbits(32)
0


