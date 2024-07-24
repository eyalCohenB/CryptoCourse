import random
from hashlib import sha256
import hashlib
SECURITY_LEVEL = 1  # Bit length for public key and hash
import math

def is_prime(number):
    """
    Checks if a number is prime.
    """
    if number % 2 == 0 and number > 2:
        return False
    return all(number % i != 0 for i in range(3, int(math.sqrt(number)) + 1, 2))

def hash512(x: bytes) -> bytes:
    hx = hashlib.sha256(x).digest()
    idx = len(hx) // 2
    return hashlib.sha256(hx[:idx]).digest() + hashlib.sha256(hx[idx:]).digest()

def hash_to_int(x: bytes) -> int:
    """Converts hash output to an integer."""
    hx = hash512(x)
    for i in range(SECURITY_LEVEL - 1):
        hx += hash512(hx)
    return int.from_bytes(hx, 'little')

def generate_keys():
    # Generate p and q, both congruent to 3 mod 4
    while True:
        p = 3 + 4 * random.randint(1, 20)
        q = 3 + 4 * random.randint(1, 20)
        if is_prime(p) and is_prime(q) and p != q:
            return p, q

def sign_rabin(p: int, q: int, message: bytes) -> tuple:
    # Calculate n, the product of p and q, which is part of the public key and used for signing.
    n = p * q
    # Initialize a counter i to 0. This will be used to add padding bytes if necessary.
    i = 0 
    # Start an infinite loop to try different values of padding (i) until a suitable hash is found.
    while True:
        # Calculate the hash of the message concatenated with i padding bytes, then take mod n of that hash.
        h = hash_to_int(message + b'\x00' * i) % n
        # Check if the hash h meets the criteria for a valid Rabin signature:
        # (1) h % p == 0 or h^(p-1)/2 % p == 1 AND (2) h % q == 0 or h^(q-1)/2 % q == 1.
        if (h % p == 0 or pow(h, (p - 1) // 2, p) == 1) and (h % q == 0 or pow(h, (q - 1) // 2, q) == 1):
            # If both conditions are met, break out of the loop as a valid hash has been found.
            break
        # If the conditions are not met, increment i to try a different padding next iteration.
        i += 1
    # Calculate the left part of the signature using Chinese Remainder Theorem (CRT) components.
    lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
    # Calculate the right part of the signature using CRT components.
    rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
    # Combine the left and right parts modulo n to form the signature.
    s = (lp + rp) % n
    # Return the signature and the padding counter as a tuple.
    return s, i
def verify(n: int, digest: bytes, s: int, padding: int) -> bool:
    return hash_to_int(digest + b'\x00' * padding) % n == (s * s) % n
