import ElipticCurveGenerator as ECDH
from user import user
from os import urandom
import salsa20_CFB
import rabin as Rabin
import binascii


def main():
    # Parameters Prep    
    random_prime1 = ECDH.draw_prime_number()
    parameters1 = ECDH.draw_parameters(random_prime1)
    n1 = 336668
    n2 = 444466
    iv = urandom(16)    # Salsa20 nonce is 16 bytes ###### This should be unique for each message ########

    # Users creation:
    alice = user("alice")
    alice.set_pKey(n1)
    alice.set_iv(iv)
    alice.set_plainText(b"Hello Bob, this is Alice Sending you A message!") # should be in Bytes! hence 'b' at start

    bob = user("bob")
    bob.set_pKey(n2)
    bob.set_iv(iv)
    bob.set_plainText(b"Hello Alice, nice hearing from you!") # should be in Bytes! hence 'b' at start

    # ECDH Key Exchange
    alice.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, alice.private_key))
    bob.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, bob.private_key))
    alice_read_bob = ECDH.calculate_point(bob.point["x3"], bob.point["y3"], parameters1["a"], random_prime1, alice.private_key)
    bob_read_alice = ECDH.calculate_point(alice.point["x3"], alice.point["y3"], parameters1["a"], random_prime1, bob.private_key)

    if alice_read_bob["x3"] == bob_read_alice["x3"] and alice_read_bob["y3"] == bob_read_alice["y3"]:
        print("Properly implemented Diffie-Hellman protocol.")
        print("Alice Sends Bob an encrypted text:")

        # Key derivation from ECDH result
        alice.salsa_key = alice_read_bob["x3"].to_bytes(32, byteorder='big')
        bob.salsa_key = bob_read_alice["x3"].to_bytes(32, byteorder='big')

        # Sign Alice's message with her private key
        signature = Rabin.sign_rabin(alice.p, alice.q,binascii.hexlify(alice.plainText))
        alice_encrypted = salsa20_CFB.salsa20_cfb_encrypt(alice.salsa_key, alice.iv, alice.plainText)
        print("Encrypted:", alice_encrypted)
        # Simulate transmission and reception
        received_encrypted = alice_encrypted
        # Decrypt the message
        bob_decrypted = salsa20_CFB.salsa20_cfb_decrypt(bob.salsa_key, bob.iv, received_encrypted)
        message = bob_decrypted.decode('utf-8')
        hexmessage = binascii.hexlify(message.encode())
        # Verify the signature with Alice's public key
        verification = Rabin.verify(alice.rabin_public,hexmessage, signature[0],signature[1])
        print("Signature Verified by Bob:", verification)
        if verification:
            print("Decrypted:", message)

main()
