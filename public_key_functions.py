def cipher_RSA(message, receiver_public_key):
    """
        :param message: int
        :param receiver_public_key: tuple (n,e), the receiver is public key
        :return: c
    """
    n = receiver_public_key[0]
    e = receiver_public_key[1]
    
    return pow(message,e,n)

def uncipher_RSA(receiver_public_key, q, p, c):
    n = receiver_public_key[0]
    e = receiver_public_key[1]
    d = modular_multiplicative_inverse(e, (p-1)*(q-1))
    
    return pow(c,d,n)
    

def cipher_ElGammal(p, alpha, m, private_key, v):
    beta = (alpha**private_key)%p
    
    return (m*pow(beta,v))%p
    

def uncipher_ElGammal(c_tuple, private_key, p):
    return ((c_tuple[1]*modular_multiplicative_inverse(pow(c_tuple[0],private_key), p))%p)

def signature_RSA(message, transmitter_private_key):
    n = transmitter_private_key[0]
    d = transmitter_private_key[1]
    
    return pow(message,d,n)

def signature_ElGammal(p, alpha, m, private_key, h):
    r = pow(alpha,h,p)
    s = ((m-private_key*r)%(p-1) * modular_multiplicative_inverse(h, p-1))%(p-1)
    
    return (r, s)
    

def modular_multiplicative_inverse(x, module):
    return pow(x, phi_euler(module)-1, module)

def phi_euler(n):
    coprimer_values_with_n = []
    
    for i in range(0, n):
        if gcd(i, n) == 1:
            coprimer_values_with_n.append(i)
    
    return len(coprimer_values_with_n)

def gcd(a, b):
	remainder = 0
	while(b > 0):
		remainder = b
		b = a % b
		a = remainder
	return a
