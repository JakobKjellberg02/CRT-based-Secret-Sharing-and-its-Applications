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

        _, shares, p_0, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, secret, None)
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

        _, shares, p_0, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, secret, None)
        shareholders = {0, 1}
        session_weight = sum(weights[i] for i in shareholders)
        self.assertTrue(session_weight <= t)

        shares_subset = [shares[i] for i in shareholders]
        primes_subset = [p_i[i] for i in shareholders]

        reconstruct_secret = share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertNotEqual(reconstruct_secret, secret)

    def test_privacy_threshold_too_big(self):
        n = 5
        T = 25
        t = 30
        weights = [2, 7, 9, 10, 12]
        p_lambda = 128
        secret = 420420

        with self.assertRaises(ValueError):
            _, shares, p_0, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, secret, None)

    def test_too_many_weights(self):
        n = 5
        T = 30
        t = 25
        weights = [2, 7, 9, 10, 12, 15]
        p_lambda = 128
        secret = 420420

        with self.assertRaises(ValueError):
            _, shares, p_0, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, secret, None)
    
    def test_weights_are_coprime(self):
        n = 5
        T = 25
        t = 15
        weights = [10,10,10,10,10]
        p_lambda = 128
        secret = 420420

        _, shares, p_0, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, secret, None)
        shareholders = {0, 1, 2}
        session_weight = sum(weights[i] for i in shareholders)
        self.assertTrue(session_weight >= T)

        shares_subset = [shares[i] for i in shareholders]
        primes_subset = [p_i[i] for i in shareholders]

        reconstruct_secret = share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertEqual(reconstruct_secret, secret)

if __name__ == "__main__":
    unittest.main()