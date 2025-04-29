import unittest
from crt_secret_sharing.crt_ss import share_distribution, share_reconstruction

class TestWithUnweightedSecretSharing(unittest.TestCase):

    def test_simple_success(self):
        _, shares, p_0, p_i = share_distribution(128, 3, 2, 420420, None, None, None, False)
        test_number = 2
        shares_subset = shares[:test_number]
        primes_subset = p_i[:test_number]
        secret = share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertEqual(secret, 420420)
    
    def test_simple_fail(self):
        _, shares, p_0, p_i = share_distribution(128, 3, 2, 420420, None, None, None, False)
        test_number = 1
        shares_subset = shares[:test_number]
        primes_subset = p_i[:test_number]
        secret = share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertIsNot(secret, 420420)

    def test_l_validation_failed(self):
        with self.assertRaises(ValueError):
            _, shares, p_0, p_i = share_distribution(16, 3, 2, 420420, 3, [43451, 43607, 59513], 
                                                     1000000000000000, False)
    
    def test_order_of_field(self):
        with self.assertRaises(ValueError):
            _, shares, p_0, p_i = share_distribution(16, 3, 2, 420420, 8, None, None, False)
    
    def test_not_prime_numbers(self):
        with self.assertRaises(ValueError):
            _, shares, p_0, p_i = share_distribution(16, 3, 2, 420420, None, [4, 6, 8], None, False)

if __name__ == '__main__':
    unittest.main()