from salsa20 import salsa20_block

def salsa20_cfb_encrypt(key, iv, plaintext):
    block_size = 64  # Salsa20 processes 64 bytes per block
    encrypted = bytearray()

    for i in range(0, len(plaintext), block_size):
        keystream = salsa20_block(key, iv, i // block_size)
        block = plaintext[i:i + block_size]
        encrypted_block = bytes(x ^ y for x, y in zip(block, keystream[:len(block)]))
        encrypted.extend(encrypted_block)
        
        iv = encrypted_block[:8]

    return bytes(encrypted)

def salsa20_cfb_decrypt(key, iv, ciphertext):
    return salsa20_cfb_encrypt(key, iv, ciphertext)
