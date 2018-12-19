import unittest

from public_key_functions import *

class CipherRSA(unittest.TestCase):

    def test_basic_cipher_RSA_1(self):
        m = 20       
        nB = 3053
        eB = 943
        receiver_public_key = (nB, eB)
        correct_result = 1237
        self.assertEqual(cipher_RSA(m, receiver_public_key), correct_result)
        
    def test_basic_cipher_RSA_2(self):
        m = 60       
        nB = 1717
        eB = 1337
        receiver_public_key = (nB, eB)
        correct_result = 145
        self.assertEqual(cipher_RSA(m, receiver_public_key), correct_result)
    
    def test_basic_cipher_RSA_3(self):
        m = 17
        nB = 4331
        eB = 971
        receiver_public_key = (nB, eB)
        correct_result = 1153    
        self.assertEqual(cipher_RSA(m, receiver_public_key), correct_result)
        
    def test_basic_uncipher_RSA_1(self):
        nB = 5429
        eB = 1871
        receiver_public_key = (nB, eB)
        p = 89
        q = 61
        c = 1008
        correct_result = 82
        self.assertEqual(uncipher_RSA(receiver_public_key, p, q, c), correct_result)
    
    def test_basic_uncipher_RSA_2(self):
        nB = 6893
        eB = 4909
        receiver_public_key = (nB, eB)
        p = 61
        q = 113
        c = 131
        correct_result = 95
        self.assertEqual(uncipher_RSA(receiver_public_key, p, q, c), correct_result)
        
    def test_basic_uncipher_RSA_3(self):
        nB = 9797
        eB = 4513
        receiver_public_key = (nB, eB)
        p = 97
        q = 101
        c = 7103
        correct_result = 22
        self.assertEqual(uncipher_RSA(receiver_public_key, p, q, c), correct_result)
        
    def test_basic_signature_RSA_1(self):
        m = 589
        nA = 7303
        dA = 1555
        transmitter_private_key = (nA, dA)
        correct_result = 7144
        self.assertEqual(signature_RSA(m, transmitter_private_key), correct_result)
    
    def test_basic_signature_RSA_2(self):
        m = 1312
        nA = 3953
        dA = 173
        transmitter_private_key = (nA, dA)
        correct_result = 1277
        self.assertEqual(signature_RSA(m, transmitter_private_key), correct_result)
    
    def test_basic_signature_RSA_3(self):
        m = 1025
        nA = 1387
        dA = 509
        transmitter_private_key = (nA, dA)
        correct_result = 170
        self.assertEqual(signature_RSA(m, transmitter_private_key), correct_result)
        

class CipherElGammal(unittest.TestCase):
    
    def test_basic_cipher_ElGammal_1(self):
        p = 251
        alpha = 90
        m = 98
        private_key = 200
        v = 183
        correct_result = 44
        self.assertEqual(cipher_ElGammal(p, alpha, m, private_key, v), correct_result)
        
    def test_basic_cipher_ElGammal_2(self):
        p = 173
        alpha = 156
        m = 118
        private_key = 112
        v = 18
        correct_result = 43
        self.assertEqual(cipher_ElGammal(p, alpha, m, private_key, v), correct_result)
        
    def test_basic_cipher_ElGammal_3(self):
        p = 317
        alpha = 183
        m = 164
        private_key = 143
        v = 48
        correct_result = 249
        self.assertEqual(cipher_ElGammal(p, alpha, m, private_key, v), correct_result)
        
    def test_basic_cipher_ElGammal_4(self):
        p = 67
        alpha = 32
        m = 14
        private_key = 22
        v = 55
        correct_result = 4
        self.assertEqual(cipher_ElGammal(p, alpha, m, private_key, v), correct_result)
    
    def test_basic_uncipher_ElGammal_1(self):
        c_tuple = (75, 40)
        private_key = 9
        p = 151
        correct_result = 56
        self.assertEqual(uncipher_ElGammal(c_tuple, private_key, p), correct_result)
        
    def test_basic_uncipher_ElGammal_2(self):
        c_tuple = (110, 3)
        private_key = 22
        p = 269
        correct_result = 181
        self.assertEqual(uncipher_ElGammal(c_tuple, private_key, p), correct_result)
        
    def test_basic_uncipher_ElGammal_3(self):
        c_tuple = (47, 11)
        private_key = 55
        p = 59
        correct_result = 49
        self.assertEqual(uncipher_ElGammal(c_tuple, private_key, p), correct_result)
        
    def test_basic_uncipher_ElGammal_4(self):
        c_tuple = (94, 328)
        private_key = 295
        p = 349
        correct_result = 63
        self.assertEqual(uncipher_ElGammal(c_tuple, private_key, p), correct_result)
    
    def test_basic_signature_ElGammal_1(self):
        p = 31
        alpha = 13
        m = 20
        private_key = 16
        h = 7
        correct_result = (22, 4)
        self.assertEqual(signature_ElGammal(p, alpha, m, private_key, h), correct_result)
    
    def test_basic_signature_ElGammal_2(self):
        p = 139
        alpha = 58
        m = 120
        private_key = 80
        h = 113
        correct_result = (68, 130)
        self.assertEqual(signature_ElGammal(p, alpha, m, private_key, h), correct_result)
    
    def test_basic_signature_ElGammal_3(self):
        p = 11
        alpha = 7
        m = 8
        private_key = 9
        h = 3
        correct_result = (2, 0)
        self.assertEqual(signature_ElGammal(p, alpha, m, private_key, h), correct_result)
        
    
if __name__ == '__main__':

    # create a suite with all tests
    test_classes_to_run = [CipherRSA, CipherElGammal]
    loader = unittest.TestLoader()
    suites_list = []
    for test_class in test_classes_to_run:
        suite = loader.loadTestsFromTestCase(test_class)
        suites_list.append(suite)

    all_tests_suite = unittest.TestSuite(suites_list)

    # run the test suite with high verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    results = runner.run(all_tests_suite)
