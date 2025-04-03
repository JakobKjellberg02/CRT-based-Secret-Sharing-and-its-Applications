from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
import sympy
from crt_secret_sharing.util_crt import modinv
from crt_secret_sharing.weighted_crt_share import WRSS_setup
from Crypto.Util.number import getPrime, GCD

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
    return int.from_bytes(hkdfsha256.derive(str(X).encode()),'big') 

def find_generator(p):
    if not sympy.isprime(p):
        raise ValueError("p must be prime to find generator")
    phi = p - 1
    factors = sympy.primefactors(phi)

    for g in range(2, p):
        is_generator = True
        for factor in factors:
            if pow(g, phi // factor, p) == 1:
                is_generator = False
                break
        if is_generator:
            return g
    raise RuntimeError(f"Could not find generator for prime {p}")

def sample_group(p_lambda):
    while True:
        q = getPrime(p_lambda)
        p_0 = 2 * q + 1
        if (GCD(q, p_0) == 1):
            small_g = 2
            return p_0, q, small_g

def keygen(p_lambda):
    p_0, q, small_g = sample_group(p_lambda)
    s = secrets.randbelow(q-1) + 1
    h = pow(small_g, s, p_0)
    return p_0, q, small_g, s, h

def encrypt(m, h, small_g, p_0, q):
    r = secrets.randbelow(q - 1)
    c1 = pow(small_g, r, p_0)
    k = pow(h, r, p_0)
    sd = secrets.randbits(32)
    k_random = randomness_extractor(sd, k, p_0)
    c2 = m ^ k_random
    h_k = universal_hashing(k)

    return (c2, sd, c1, h_k), r

def langrange_coeffs(index, participants, p_i):
    mod = p_i[index]
    P = 1
    for j in participants:
        if index != j:
            p_j = p_i[j]
            P *= p_j
    inv_P = modinv(P, mod)
    return P * inv_P
    
def partial_decrypt(index, share, c1, p_0, participants, p_i):
    P_S = 1
    for i in participants:
        P_S *= p_i[i]
    lambda_i = langrange_coeffs(index, participants, p_i)
    exp = (share * lambda_i) % P_S
    group_order = p_0 - 1
    if group_order <= 0:
         raise ValueError("Invalid group order (p_0 <= 1)")
    final_exp = exp % group_order
    mu_i = pow(c1, final_exp, p_0)
    return mu_i

def reconstruct(partial_decryptions, c1, h_k, p_0, participants, p_i):
    mu = 1
    for i in participants:
        mu = (mu * partial_decryptions[i]) % p_0
    P = 1
    for i in participants:
        P *= p_i[i]
    
    max_overflow = len(participants)
    print(f"Reconstructing: mu={mu}, c1={c1}, P_S={P}, p_0={p_0}")
    for j in range(max_overflow + 1):
        exp_inv = (-j * P) % p_0
        print("test")

        inv_factor = pow(c1, exp_inv, p_0) 
        potential_k = (mu * inv_factor) % p_0 

        if universal_hashing(potential_k) == h_k:
            return potential_k
    
    print("Reconstruction failed: No matching hash")
    return None

def decrypt(c2, reconstruction, sd, p_0):
    k_random = randomness_extractor(sd, reconstruction, p_0)
    return c2 ^ k_random

            
if __name__ == "__main__":
    n = 5
    T = 57
    t = 50
    weights = [16,17,18,19,20]
    p_lambda = 32

    small_g, q, p_0, small_s, h = keygen(p_lambda)

    big_s, shares, p_i = WRSS_setup(p_0, small_s, weights, T, t, p_lambda)

    participants = {1,2,3}
    session_weight = sum(weights[i] for i in participants)

    plaintext = 420420420
    ciphertext, random_r = encrypt(plaintext, h, small_g, p_0, q)
    c2, seed, c1, h_k = ciphertext

    partial_decryptions = {}
    for i in participants:
        mu_i = partial_decrypt(i, shares[i], c1, p_0, participants, p_i)
        partial_decryptions[i] = mu_i

    k_constructed = reconstruct(partial_decryptions, c1, h_k, p_0, participants, p_i)
    decrypted_message = decrypt(c2, k_constructed, seed, p_0)
    print(decrypted_message)
    


