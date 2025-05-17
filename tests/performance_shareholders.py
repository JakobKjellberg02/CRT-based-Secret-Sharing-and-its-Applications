import matplotlib.pyplot as plt
from time import time
from crt_secret_sharing.el_gamal_encryption import keygen, encrypt
from crt_secret_sharing.weighted_crt_ss import weighted_setup

def test_of_elgamal(n, t, T, weights, p_lambda):
    p_0, q, small_g, small_s, pk = keygen(p_lambda)

    start_setup = time()
    _, _, q, _, _ = weighted_setup(p_lambda, n, T, t, weights, small_s, q)
    end_setup = time()

    plaintext = 420420
    start_encrypt = time()
    ciphertext, _ = encrypt(plaintext, pk, small_g, p_0, q)
    end_encrypt = time()
    c2, seed, c1, h_k = ciphertext

    return {
        "wrss_time" : end_setup - start_setup,
        "encrypt_time" : end_encrypt - start_encrypt,
    }

if __name__ == "__main__":
    user_counts = list(range(3, 30))  
    p_lambda = 256

    wrss_times = []
    encrypt_times = []

    for n in user_counts:
        weights = [50 + i for i in range(1, n + 1)]
        total_weight = sum(weights)
        t = int(0.3 * total_weight)     
        T = int(0.7 * total_weight)   

        result = test_of_elgamal(n, t, T, weights, p_lambda)

        wrss_times.append(result["wrss_time"])
        encrypt_times.append(result["encrypt_time"])

    # Plotting results
    plt.figure(figsize=(12, 6))
    plt.plot(user_counts, wrss_times, marker='o', label='WRSS Setup (s)')
    plt.plot(user_counts, encrypt_times, marker='s', label='Encryption (s)')

    plt.title("Performance of ElGamal + WRSS vs. Number of Users")
    plt.xlabel("Number of Users (n)")
    plt.ylabel("Time (s)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()


    