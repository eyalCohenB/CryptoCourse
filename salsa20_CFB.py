from salsa20 import salsa20_block

def salsa20_cfb_encrypt(key, iv, plaintext):
    block_size = 64  # Salsa20 processes 64 bytes per block
    encrypted = bytearray()

    for i in range(0, len(plaintext), block_size):
        # Generate keystream block
        keystream = salsa20_block(key, iv, i // block_size)
        
        # Encrypt the current block
        block = plaintext[i:i + block_size]
        encrypted_block = bytes(x ^ y for x, y in zip(block, keystream[:len(block)]))
        
        # Append the encrypted block to the result
        encrypted.extend(encrypted_block)
        
        # Update the IV (nonce) with the output block for CFB feedback
        iv = encrypted_block[:8]  # Use the first 8 bytes of the encrypted block as the next IV

    return bytes(encrypted)

def salsa20_cfb_decrypt(key, iv, ciphertext):
    # Decryption in CFB is symmetric to encryption
    return salsa20_cfb_encrypt(key, iv, ciphertext)
