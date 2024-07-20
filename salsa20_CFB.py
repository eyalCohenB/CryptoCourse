from Crypto.Cipher import Salsa20
from os import urandom

def salsa20_cfb_encrypt(key, iv, plaintext):
    block_size = 64  # Salsa20 processes 64 bytes per block
    encrypted = bytearray()

    for i in range(0, len(plaintext), block_size):
        # Create a new cipher for each block
        cipher = Salsa20.new(key=key, nonce=iv)
        
        # Encrypt a block-sized chunk of zeros to generate keystream
        keystream = cipher.encrypt(bytes([0] * block_size))
        
        # Encrypt the current block
        block = plaintext[i:i+block_size]
        encrypted_block = bytes(x ^ y for x, y in zip(block, keystream[:len(block)]))
        
        # Append the encrypted block to the result
        encrypted.extend(encrypted_block)
        
        # Update the IV (nonce) with the output block for CFB feedback
        iv = encrypted_block[:8]  # Use the first 8 bytes of the encrypted block as the next IV

    return bytes(encrypted)

def salsa20_cfb_decrypt(key, iv, ciphertext):
    # Decryption in CFB is symmetric to encryption
    return salsa20_cfb_encrypt(key, iv, ciphertext)

# Key and IV setup
key = urandom(32)  # Salsa20 requires a 32-byte key
iv = urandom(8)    # Salsa20 nonce is 8 bytes

# Example plaintext
plaintext = b"Hello, this is a test of Salsa20 with CFB mode!"
# Encrypt and decrypt
encrypted = salsa20_cfb_encrypt(key, iv, plaintext)
print("Encrypted:", encrypted)
decrypted = salsa20_cfb_decrypt(key, iv, encrypted)
print("Decrypted:", decrypted)
