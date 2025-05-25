import csv
import matplotlib.pyplot as plt
from time import time
from crt_secret_sharing.el_gamal_encryption import keygen, encrypt, partial_decrypt, decrypt, reconstruct
from crt_secret_sharing.weighted_crt_ss import weighted_setup

def export_efficiency_to_csv(results, filename):
    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = ['shareholders', 't', 'T', 'encrypt_runtime', 'partial_runtime', 'recon_runtime', 'decrypt_runtime']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in results:
            writer.writerow(row)

def plot_efficiency(results):
    shareholders = [r['shareholders'] for r in results]
    partial_runtime = [r['partial_runtime'] for r in results]
    recon_runtime = [r['recon_runtime'] for r in results]
    decrypt_runtime = [r['decrypt_runtime'] for r in results]

    plt.figure(figsize=(12, 6))
    plt.plot(shareholders, partial_runtime, marker='o', label='Partial Decryption (s)')
    plt.plot(shareholders, recon_runtime, marker='s', label='Reconstruction (s)')
    plt.plot(shareholders, decrypt_runtime, marker='^', label='Total Decryption (s)')

    plt.title("Decryption Performance vs Number of Shareholders")
    plt.xlabel("Number of Shareholders in Group")
    plt.ylabel("Time (s)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def test_of_elgamal(start, end):
    result = []
    p_lambda = 256
    weight_limit = 50

    weights = [weight_limit + i for i in range(1, end + 1)]
    t = 50  
    T = 150
    p_0, q, small_g, small_s, pk = keygen(p_lambda)

    _, shares, q, p_i, _ = weighted_setup(p_lambda, end, T, t, weights, small_s, q)
    plaintext = 420420
    ciphertext, _ = encrypt(plaintext, pk, small_g, p_0, q)
    c2, seed, c1, h_k = ciphertext

    for x in range(start, end):
        shareholders = set(range(1, x+1))
        partial_decryptions = {}
        start_partial = time()
        for i in shareholders:
            mu_i = partial_decrypt(i, shares[i], c1, p_0, shareholders, p_i, q)
            partial_decryptions[i] = mu_i
        end_partial = time() - start_partial

        start_recon = time()
        k_constructed = reconstruct(partial_decryptions, c1, h_k, p_0, shareholders, p_i, q)
        end_recon = time() - start_recon
        start_decryp = time()
        decrypted_message = decrypt(c2, k_constructed, seed)
        end_decryp = time() - start_decryp
        assert(decrypted_message == 420420)

        result.append({
            'shareholders' : x,
            't' : t,
            'T' : T,
            'partial_runtime' : end_partial,
            'recon_runtime' : end_recon,
            'decrypt_runtime' : end_decryp,
        })
    return result

if __name__ == "__main__":
    start = 3
    end = 100
    results = test_of_elgamal(start, end)
    export_efficiency_to_csv(results, f"performance_reconstruct_{start}to{end - 1}_256bits.csv")
    plot_efficiency(results)


    