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
    n = p * q
    i = 0 
    while True:
        h = hash_to_int(message + b'\x00' * i) % n
        if (h % p == 0 or pow(h, (p - 1) // 2, p) == 1) and (h % q == 0 or pow(h, (q - 1) // 2, q) == 1):
            break
        i += 1
    lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
    rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
    s = (lp + rp) % n
    return s, i

def verify(n: int, digest: bytes, s: int, padding: int) -> bool:
    return hash_to_int(digest + b'\x00' * padding) % n == (s * s) % n
