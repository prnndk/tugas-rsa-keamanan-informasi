import random
from math import gcd

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_prime(start=100, end=500):
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num

# Function to compute modular inverse using Extended Euclidean Algorithm
def modular_inverse(e, phi):
    t1, t2 = 0, 1
    r1, r2 = phi, e
    while r2 > 0:
        q = r1 // r2
        t1, t2 = t2, t1 - q * t2
        r1, r2 = r2, r1 - q * r2
    return t1 % phi

# RSA Key generation
def generate_keys():
    p = generate_prime()
    q = generate_prime()
    while p == q:
        q = generate_prime()
    
    n = p * q  # RSA modulus
    phi = (p - 1) * (q - 1)  # Euler's totient

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.choice([3, 5, 17, 257, 65537])  # Commonly used public exponents
    while gcd(e, phi) != 1:
        e = random.randint(2, phi)

    # Calculate d (private exponent)
    d = modular_inverse(e, phi)

    # Return public and private keys
    return ((n, e), (n, d))

def RSAencrypt(message, public_key):
    n, e = public_key
    return [pow(ord(char), e, n) for char in message]

def RSAdecrypt(ciphertext, private_key):
    n, d = private_key
    return ''.join([chr(pow(char, d, n)) for char in ciphertext])

# Convert ciphertext list to a string for transmission
def ciphertext_to_string(ciphertext):
    return ' '.join(map(str, ciphertext))

# Convert ciphertext string back to a list of integers
def string_to_ciphertext(ciphertext_string):
    return list(map(int, ciphertext_string.split()))
