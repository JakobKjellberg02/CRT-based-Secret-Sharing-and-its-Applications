from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
from crt_secret_sharing.util_primes import generate_prime
from crt_secret_sharing.util_crt import modinv
from crt_secret_sharing.weighted_crt_share import WRSS_setup
from math import prod

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

def sample_group(p_lambda):
    p_0 = generate_prime(p_lambda)
    small_g = secrets.randbelow(p_0 - 2) + 2
    return small_g, p_0

def keygen(p_lambda):
    small_g, p_0 = sample_group(p_lambda)
    s = secrets.randbelow(p_0-1)
    h = pow(small_g, s, p_0)
    return small_g, p_0, s, h

def encrypt(m, h, small_g, p_0):
    r = secrets.randbelow(p_0 - 1)
    c1 = pow(small_g, r, p_0)
    k = pow(h, r, p_0)
    sd = secrets.randbits(32)
    k_random = randomness_extractor(sd, k, p_0)
    c2 = m ^ k_random
    h_k = universal_hashing(k)

    return (c2, sd, c1, h_k), r

def reconstruct(c1, P, h_k, p_0, shares_subset, prime_subset):
    S = 0
    for s_i, p_i in zip(shares_subset, prime_subset):
        Q_i = P // p_i
        inv_Q_i = modinv(Q_i, p_i)
        S += s_i * Q_i * inv_Q_i
    S = S % P  
    s = S % p_0 
    k = pow(c1, s, p_0)  
    if universal_hashing(k) != h_k:
        raise ValueError("Reconstruction failed verification!")
    return k


def decrypt(c2, reconstruction, sd, p_0):
    k_random = randomness_extractor(sd, reconstruction, p_0)
    return c2 ^ k_random


if __name__ == "__main__":
    T = 19
    t = 12
    weights = [3,7,9,10,12]
    p_lambda = 256

    small_g, p_0, small_s, h = keygen(p_lambda)

    big_s, shares, p_i = WRSS_setup(p_0, small_s, weights, T, t, p_lambda)

    test_number = 3
    shares_subset = shares[:test_number]
    prime_subset = p_i[:test_number]

    print("## ElGamal Encryption ##")
    plain_text = 420420  
    ciphertext, random_r = encrypt(plain_text, h, small_g, p_0)

    k_reconstructed = reconstruct(ciphertext[2], prod(prime_subset), ciphertext[3], p_0, shares_subset, prime_subset)
    decrypted_message = decrypt(ciphertext[0], k_reconstructed, ciphertext[1], p_0)
    print("Decrypted: ", decrypted_message)





