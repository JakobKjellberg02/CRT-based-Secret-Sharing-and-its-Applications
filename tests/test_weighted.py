import unittest
import crt_secret_sharing.weighted_crt_ss as wcs
import crt_secret_sharing.util_primes as up


class TestWithWeightedSecretSharing(unittest.TestCase):

    def test_weighted(self):
        n = 5
        T = 19
        t = 12
        weights = [3,7,9,10,12]
        small_s = 420420
        p_lambda = 64

        c = max(1, p_lambda // (T - t + 1))

        p_0 = up.generate_prime(p_lambda)
        p_i = up.generate_weighted_party_primes(p_0, weights, c)

        P_min = wcs.approx_min_product_weights(T, weights, p_i)
        P_max = wcs.approx_max_product_weights(t, weights, p_i)
        L = wcs.compute_random_L(P_min, P_max, p_0, p_lambda)

        big_s, shares = wcs.share_distribution(small_s, p_0, p_i, L)

        test_number = 3
        shares_subset = shares[:test_number]
        primes_subset = p_i[:test_number]

        reconstructed_secret = wcs.share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertEqual(reconstructed_secret, small_s)

if __name__ == '__main__':
    unittest.main()

        