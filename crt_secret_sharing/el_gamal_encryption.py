from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
from typing import List, Optional
from crt_secret_sharing.util_crt import modinv
from crt_secret_sharing.weighted_crt_ss import weighted_setup
from Crypto.Util.number import getPrime, isPrime

def universal_hashing(x : int) -> int:
    """
    Universal hash function which uses SHA256.

    Parameters
    ----------
        x : int 
            Input for universal hash function.

    Returns
    -------
        integer : int
            SHA256 hash integer.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(str(x).encode())
    return int.from_bytes(digest.finalize(), 'big')

def randomness_extractor(s : int, X : int) -> int:
    """
    Randomness extractor from ElGamal session key using HKDF-SHA256.

    Parameters
    ----------
        s : int 
            Seed for the randomness extractor.
        X : int
            Input for randomness extractor.

    Returns
    -------
        integer : int
            Extracted pseudo-random integer 256 bit.

    """
    hkdfsha256 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=s.to_bytes(32, 'big'), # Will get converted from int -> bytes
        info=b'wrss-elgamal'
    )
    return int.from_bytes(hkdfsha256.derive(str(X).encode()),'big') 

def find_generator(p : int, q : int) -> int:
    """
    Find generator g of a subgroup of order q in Z_p*.

    Parameters
    ----------
        p : int 
            Safe prime.
        q : int 
            Order.

    Returns
    -------
        g : int
            Generator.
    """
    if (p - 1) % q != 0:
        raise ValueError("q must divide p-1")

    for g in range(2, p):
        if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
            return g
        
    raise RuntimeError(f"Could not find generator of order {q} for prime {p}")

def sample_group(p_lambda : int) -> tuple[int, int, int]:
    """
    Sample safe prime p_0 and finds generator g.

    Parameters
    ----------
        p_lambda : int
            Security parameter of bit length.

    Returns
    -------
        p_0 : int
            Safe prime.
        q : int
            Order.
        small_g : int
            Generator.
    """
    while True:
        q = getPrime(p_lambda)
        p_0 = 2 * q + 1
        if isPrime(p_0):
            small_g = find_generator(p_0, q)
            return p_0, q, small_g

def keygen(p_lambda):
    """
    Key generation for ElGamal scheme.

    Parameters
    ----------
        p_lambda : int
            Security parameter of bit length.

    Returns
    -------
        p_0 : int
            Safe prime.
        q : int
            Order.
        small_g : int
            Generator.
        s : int 
            Secret share.
        pk : int
            Public key.

    """
    p_0, q, small_g = sample_group(p_lambda)
    s = secrets.randbelow(q-1) + 1
    pk = pow(small_g, s, p_0)
    return p_0, q, small_g, s, pk

def encrypt(m : int, pk : int, small_g : int, p_0 : int, q : int) -> tuple[tuple[int, int, int, int], int]:
    """
    ElGamal encryption.

    Parameters
    ----------
        m : int
            Plaintext message.
        pk : int 
            Public key.
        small_g : int
            Generator.
        p_0 : int
            Safe prime.
        q : int
            Order.

    Returns
    -------
        tuple : tuple[int, int, int, int]
            Encrypted ciphertext
        r : int
            random integer.
    """
    # Generate random exponent
    r = secrets.randbelow(q - 1) + 1
    # g^r
    c1 = pow(small_g, r, p_0)
    # pk^r
    pub = pow(pk, r, p_0)
    # seed
    sd = secrets.randbits(16)
    # Ext(sd,pk^r)
    k_random = randomness_extractor(sd, pub)
    # m \oplus Ext(sd, pk^r)
    c2 = m ^ k_random
    # h_k(pk^r)
    h_k = universal_hashing(pub)
    return (c2, sd, c1, h_k), r

def lagrange_coeffs(index : int, shareholders : set[int], p_i : List[int]) -> int:
    """
    Computing Lagrange coefficient for shareholder.

    Parameters
    ----------
        index : int
            Index of the shareholder.
        shareholders : set[int]
            Indices of the shareholders.
        p_i : List[int]
            List of distinct coprime integers for each shareholder.

    Returns
    -------
        lang_coeff : int ->
            Lagrange interpolation coefficient.
    """
    P = 1
    for j in shareholders:
        P *= p_i[j]
    p_i_index = p_i[index]
    Q_i = P // p_i_index
    Q_inv_i = modinv(Q_i, p_i_index)
    return (Q_i * Q_inv_i) % P
    
def partial_decrypt(index : int, share : int, c1 : int, p_0 : int, shareholders : set[int], 
                    p_i : List[int], q : int) -> int:
    """
    Partial decryption of ciphertext for a shareholder.

    Parameters
    ----------
        index : int
            Index of the shareholder.
        share : int
            Shareholder value.
        c1 : int
            g^r.
        p_0 : int
            Safe prime.
        shareholders : set[int]
            Indices of the shareholders.
        p_i : List[int]
            List of distinct coprime integers for each shareholder.
        q : int
            Order.

    Returns
    -------
        mu_i : int
            Partial decryption.
    
    """
    P_S = 1
    for i in shareholders:
        P_S *= p_i[i]
    lambda_i = lagrange_coeffs(index, shareholders, p_i)
    exp = (share * lambda_i) % P_S
    final_exp = exp % q
    mu_i = pow(c1, final_exp, p_0)
    return mu_i

def reconstruct(partial_decryptions : dict, c1 : int, h_k : int, p_0 : int, shareholders : set[int], 
                p_i : List[int], q : int) -> (int | None):
    """
    Reconstruction of the key using Shareholders.

    Parameters
    ----------
        index : dict
            Partial decryptions
        c1 : int
            g^r.
        h_k : int
            Hashed value for comparison
        p_0 : int
            Safe prime.
        shareholders : set[int]
            Indices of the shareholders.
        p_i : List[int]
            List of distinct coprime integers for each shareholder.
        q : int
            Order.

    Returns
    -------
        potential_k : int
            Potential candidate for value.
    """
    mu = 1
    for i in shareholders:
        mu = (mu * partial_decryptions[i]) % p_0
    P = 1
    for i in shareholders:
        P *= p_i[i]
    
    max_overflow = len(shareholders)
    for j in range(max_overflow + 1):
        exp_inv = (-j * P) % q

        inv_factor = pow(c1, exp_inv, p_0) 
        potential_k = (mu * inv_factor) % p_0 

        if universal_hashing(potential_k) == h_k:
            return potential_k
    
    raise ValueError("Reconstruction failed: No matching hash")

def decrypt(c2 : int, reconstruction : int, sd : int) -> int:
    """
    ElGamal Decryption.

    Parameters
    ----------
        c2 : int
            XORed ciphertext.
        reconstruction : int
            Reconstructed for correct j.
        sd : int
            Seed.

    Returns
    -------
        decrypted : int
            Decrypted message.
    """
    k_random = randomness_extractor(sd, reconstruction)
    return c2 ^ k_random

if __name__ == "__main__":
    n = 5
    T = 25
    t = 15
    weights = [3,7,9,10,12]
    p_lambda = 256

    p_0, q, small_g, small_s, pk = keygen(p_lambda)

    big_s, shares, q, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, small_s, q)

    shareholders = {0,3,4}
    session_weight = sum(weights[i] for i in shareholders)
    print(f"Session weight ({session_weight})")

    plaintext = 420420
    ciphertext, random_r = encrypt(plaintext, pk, small_g, p_0, q)
    c2, seed, c1, h_k = ciphertext

    partial_decryptions = {}
    for i in shareholders:
        mu_i = partial_decrypt(i, shares[i], c1, p_0, shareholders, p_i, q)
        partial_decryptions[i] = mu_i

    k_constructed = reconstruct(partial_decryptions, c1, h_k, p_0, shareholders, p_i, q)
    decrypted_message = decrypt(c2, k_constructed, seed)
    print(decrypted_message)
    