import unittest
from math import prod
import crt_secret_sharing.poly_share_distribution as sd
import crt_secret_sharing.poly_share_reconstruction as sr
import crt_secret_sharing.unweighted_crt_share as wcs

class TestWithALowPrimeAndLowThreshold(unittest.TestCase):

    def test_lowprime_poly(self):
        d_0 = 3        
        p = 283          
        threshold = (7,3)    
        n,t = threshold
        m_0, moduli = sd.scheme_setup(p, d_0, n, t)
        s, alpha = sd.generate_secret(p, d_0, moduli, t)
        f, created_shares = sd.shares(s, alpha, m_0, moduli)
        reconstruction_index = [0,1,2,3]
        reconstruct_shares = [created_shares[i] for i in reconstruction_index]
        reconstruct_moduli = [moduli[i] for i in reconstruction_index]

        reconstructed_the_secret = sr.reconstruct_secret(reconstruct_shares, reconstruct_moduli
                                                    , m_0, p)
        self.assertEqual(reconstructed_the_secret, s)
    
    def test_lowprime_unweighted(self):
        threshold = (5,3)    
        n,t = threshold
        small_s = 420420
        p_lambda = 64
        p_0 = wcs.generate_prime(p_lambda)
        p_i = wcs.generate_party_primes(n, p_0, p_lambda)

        P_min = prod(sorted(p_i)[:t])
        L = (P_min // (p_0 + 1)) - 1 

        big_s, shares = wcs.share_distribution(small_s, p_0, p_i, L)
        
        test_number = 3
        shares_subset = shares[:test_number]
        primes_subset = p_i[:test_number]
        reconstructed_the_secret = wcs.share_reconstruction(p_0, primes_subset, shares_subset)
        self.assertEqual(reconstructed_the_secret, small_s)


if __name__ == '__main__':
    unittest.main()

        