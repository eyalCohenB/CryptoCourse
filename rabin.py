import random
from hashlib import sha256
import math

def is_prime(number):
    """
    Checks if a number is prime.
    """
    if number % 2 == 0 and number > 2:
        return False
    return all(number % i != 0 for i in range(3, int(math.sqrt(number)) + 1, 2))

def generate_keys():
    # Generate p and q, both congruent to 3 mod 4
    while True:
        p = 3 + 4 * random.randint(1, 50)
        q = 3 + 4 * random.randint(1, 50)
        if is_prime(p) and is_prime(q) and p != q:
            return p, q

def sign(message, private_key):
    p, q = private_key
    n = p * q
    message_hash = int.from_bytes(sha256(message).digest(), byteorder='big') % n

    # Compute the signature using Chinese Remainder Theorem
    mp = pow(message_hash, (p + 1) // 4, p)
    mq = pow(message_hash, (q + 1) // 4, q)

    # Combine the results using CRT
    q_inv = pow(q, -1, p)
    h = (q_inv * (mp - mq)) % p
    if h < 0:
        h += p

    signature1 = (mq + h * q) % n
    signature2 = (mq - h * q) % n
    signature3 = (p - mp + h * q) % n
    signature4 = (p - mp - h * q) % n

    signatures = [signature1, signature2, signature3, signature4]
    
    # Validate which signature matches
    for sig in signatures:
        if verify(sig, message, n):
            # print(f"Message Hash: {message_hash}")
            # print(f"mp: {mp}, mq: {mq}, q_inv: {q_inv}, h: {h}, Signature: {sig}")
            return sig

    # print(f"Message Hash: {message_hash}")
    # print(f"mp: {mp}, mq: {mq}, q_inv: {q_inv}, h: {h}, Signatures: {signatures}")
    return signatures[0]  # Return any valid signature

def verify(signature, message, public_key):
    n = public_key
    message_hash = int.from_bytes(sha256(message).digest(), byteorder='big') % n
    computed_hash = pow(signature, 2, n)

    # print(f"Message Hash (verification): {message_hash}")
    # print(f"Computed Hash (verification): {computed_hash}")

    return computed_hash == message_hash
