import unittest
from crt_secret_sharing.weighted_crt_ss import weighted_setup, share_reconstruction

class TestWithWeightedSecretSharing(unittest.TestCase):

    def test_simple_succes(self):
        n = 5
        T = 25
        t = 10 
        weights = [2, 7, 9, 10, 12]
        p_lambda = 128
        secret = 420420

        big_S, shares, p_0, p_i = weighted_setup(p_lambda, n, T, t, weights, secret, None)
        shareholders = {1, 3, 4}
        session_weight = sum(weights[i] for i in shareholders)
        self.assertTrue(session_weight >= T)

        shares_subset = [shares[i] for i in shareholders]
        primes_subset = [p_i[i] for i in shareholders]

        reconstruct_secret = share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertEqual(reconstruct_secret, secret)

    def test_simple_fail(self):
        n = 5
        T = 25
        t = 10 
        weights = [2, 7, 9, 10, 12]
        p_lambda = 128
        secret = 420420

        big_S, shares, p_0, p_i = weighted_setup(p_lambda, n, T, t, weights, secret, None)
        shareholders = {0, 1}
        session_weight = sum(weights[i] for i in shareholders)
        self.assertTrue(session_weight <= t)

        shares_subset = [shares[i] for i in shareholders]
        primes_subset = [p_i[i] for i in shareholders]

        reconstruct_secret = share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertNotEqual(reconstruct_secret, secret)

if __name__ == "__main__":
    unittest.main()