import unittest
from crt_secret_sharing.el_gamal_encryption import keygen, encrypt, partial_decrypt, decrypt, reconstruct
from crt_secret_sharing.weighted_crt_ss import weighted_setup

class TestWithEncryption(unittest.TestCase):

    def test_simple_success(self):
        n = 5
        T = 25
        t = 15
        weights = [3,7,9,10,12]
        p_lambda = 256

        p_0, q, small_g, small_s, pk = keygen(p_lambda)

        _, shares, q, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, small_s, q)

        shareholders = {0,3,4}
        plaintext = 420420
        ciphertext, _ = encrypt(plaintext, pk, small_g, p_0, q)
        c2, seed, c1, h_k = ciphertext

        partial_decryptions = {}
        for i in shareholders:
            mu_i = partial_decrypt(i, shares[i], c1, p_0, shareholders, p_i, q)
            partial_decryptions[i] = mu_i

        k_constructed = reconstruct(partial_decryptions, c1, h_k, p_0, shareholders, p_i, q)
        decrypted_message = decrypt(c2, k_constructed, seed)
        assert(decrypted_message == 420420)
    
    def test_simple_fail(self):
        n = 5
        T = 25
        t = 15
        weights = [3,7,9,10,12]
        p_lambda = 256

        p_0, q, small_g, small_s, pk = keygen(p_lambda)

        _, shares, q, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, small_s, q)

        shareholders = {0,3}
        plaintext = 420420
        ciphertext, _ = encrypt(plaintext, pk, small_g, p_0, q)
        _, _, c1, h_k = ciphertext

        partial_decryptions = {}
        for i in shareholders:
            mu_i = partial_decrypt(i, shares[i], c1, p_0, shareholders, p_i, q)
            partial_decryptions[i] = mu_i

        with self.assertRaises(ValueError):
            reconstruct(partial_decryptions, c1, h_k, p_0, shareholders, p_i, q)
    
    def test_simple_fail_in_gap(self):
        n = 5
        T = 25
        t = 15
        weights = [3,7,9,10,12]
        p_lambda = 256

        p_0, q, small_g, small_s, pk = keygen(p_lambda)

        _, shares, q, p_i, _ = weighted_setup(p_lambda, n, T, t, weights, small_s, q)

        shareholders = {2,3}
        plaintext = 420420
        ciphertext, _ = encrypt(plaintext, pk, small_g, p_0, q)
        _, _, c1, h_k = ciphertext

        partial_decryptions = {}
        for i in shareholders:
            mu_i = partial_decrypt(i, shares[i], c1, p_0, shareholders, p_i, q)
            partial_decryptions[i] = mu_i

        with self.assertRaises(ValueError):
            reconstruct(partial_decryptions, c1, h_k, p_0, shareholders, p_i, q)

if __name__ == "__main__":
    unittest.main()