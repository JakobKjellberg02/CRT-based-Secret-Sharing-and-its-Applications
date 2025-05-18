import csv
import matplotlib.pyplot as plt
from time import time
from crt_secret_sharing.el_gamal_encryption import keygen, encrypt
from crt_secret_sharing.weighted_crt_ss import weighted_setup

def export_efficiency_to_csv(results, filename):
    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = ['shareholders', 't', 'T', 'setup_runtime', 'encrypt_runtime']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in results:
            writer.writerow(row)

def plot_efficiency(results):
    shareholders = [r['shareholders'] for r in results]
    setup_runtime = [r['setup_runtime'] for r in results]
    encrypt_runtime = [r['encrypt_runtime'] for r in results]
    plt.figure(figsize=(12, 6))
    plt.plot(shareholders, setup_runtime, marker='o', label='WRSS Setup (s)')
    plt.plot(shareholders, encrypt_runtime, marker='s', label='Encryption (s)')
    plt.title("Performance of ElGamal + WRSS vs Number of Users")
    plt.xlabel("Number of Shareholders (n)")
    plt.ylabel("Time (s)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def test_of_elgamal(start, end, p_lambda, sameweights=False):
    result = []
    shareholders = list(range(start, end))  
    p_lambda = 256
    weight_limit = 50

    for n in shareholders:
        if sameweights:
            weights = [weight_limit for _ in range(1, n + 1)]
        else:
            weights = [weight_limit + i for i in range(1, n + 1)]
        t = weight_limit    
        T = (weight_limit * 3)
        p_0, q, small_g, small_s, pk = keygen(p_lambda)

        start_setup = time()
        _, _, q, _, _ = weighted_setup(p_lambda, n, T, t, weights, small_s, q)
        end_setup = time() - start_setup

        plaintext = 420420
        start_encrypt = time()
        _, _ = encrypt(plaintext, pk, small_g, p_0, q)
        end_encrypt = time() - start_encrypt

        result.append({
            'shareholders' : n,
            't' : t,
            'T' : T,
            'setup_runtime' : end_setup,
            'encrypt_runtime' : end_encrypt
        })
    return result

if __name__ == "__main__":
    start = 3
    end = 30
    p_lambda = 256
    results = test_of_elgamal(start, end, p_lambda)
    export_efficiency_to_csv(results, f"performance_shareholders_{start}to{end - 1}_{p_lambda}bits.csv")
    plot_efficiency(results)
    results = test_of_elgamal(start, end, p_lambda, sameweights=True)
    export_efficiency_to_csv(results, f"performance_shareholders_{start}to{end - 1}_sameW_{p_lambda}bits.csv")
    plot_efficiency(results)

    