import matplotlib.pyplot as plt
import csv
from time import time
from crt_secret_sharing.weighted_crt_ss import weighted_setup, share_reconstruction

def export_efficiency_to_csv(results, filename="wrss_efficiency.csv"):
    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = ['t', 'c', 'avg_prime_bits', 'total_prime_bits', 'runtime']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in results:
            writer.writerow(row)

def plot_efficiency(results):
    t_vals = [r['t'] for r in results]
    c_vals = [r['c'] for r in results]
    avg_primes = [r['avg_prime_bits'] for r in results]
    total_bits = [r['total_prime_bits'] for r in results]
    runtimes = [r['runtime'] for r in results]

    fig, ax1 = plt.subplots()
    ax1.set_xlabel("Privacy Threshold t")
    ax1.set_ylabel("Average Prime Size (bits)", color="tab:blue")
    ax1.plot(t_vals, avg_primes, 'o-', color="tab:blue", label="Avg Prime Size")
    ax1.tick_params(axis='y', labelcolor="tab:blue")

    ax2 = ax1.twinx()
    ax2.set_ylabel("Total Share Size (bits)", color="tab:green")
    ax2.plot(t_vals, total_bits, 'x--', color="tab:green", label="Total Share Size")
    ax2.tick_params(axis='y', labelcolor="tab:green")

    fig.tight_layout()
    plt.title("WRSS Efficiency vs Privacy Threshold")
    plt.show()

    plt.figure()
    plt.plot(t_vals, runtimes, 's-', color="tab:red")
    plt.xlabel("Privacy Threshold t")
    plt.ylabel("Setup + Reconstruction Time (s)")
    plt.title("Efficiency of WRSS")
    plt.grid(True)
    plt.show()

def test_of_efficiency(p_lambda, weights, n, T):
    result = []
    for t in range(0,100):
        shareholders = {1,2,3}
        start_time = time()
        _, shares, p_0, p_i, c = weighted_setup(p_lambda, n, T, t, weights, 420420, None)
        shares_subset = [shares[i] for i in shareholders]
        primes_subset = [p_i[i] for i in shareholders]
        reconstructed_secret = share_reconstruction(p_0, primes_subset, shares_subset)
        stop_time = time() -  start_time
        assert(reconstructed_secret == 420420)

        prime_size = [p.bit_length() for p in p_i]
        avg_prime = sum(prime_size) / len(prime_size)
        total_prime = sum(prime_size)

        result.append({
            't' : t,
            'c' : c,
            'avg_prime_bits' : avg_prime,
            'total_prime_bits' : total_prime,
            'runtime' : stop_time
        })
    return result

if __name__ == "__main__":
    p_lambda = 128
    weights = [60, 80, 100, 120, 140]
    n = len(weights)
    results = test_of_efficiency(p_lambda, weights, n, 300)
    plot_efficiency(results)
    export_efficiency_to_csv(results, "wrss_efficiency_128bits.csv")

    