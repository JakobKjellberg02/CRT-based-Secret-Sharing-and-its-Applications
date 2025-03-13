import unittest
import crt_secret_sharing.poly_share_distribution as sd
import crt_secret_sharing.poly_share_reconstruction as sr

class TestWithALowPrimeAndLowThreshold(unittest.TestCase):

    def test_low_prime(self):
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

if __name__ == '__main__':
    unittest.main()

        