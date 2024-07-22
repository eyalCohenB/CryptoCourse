import ElipticCurveGenerator as ECDH
from user import user
from os import urandom
import salsa20_CFB
import rabin as Rabin

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

    # Sign Alice's message with her private key
    signature = Rabin.sign(alice.plainText, (alice.p, alice.q))

    # Bob verifies the signature with Alice's public key
    verification = Rabin.verify(signature, alice.plainText, alice.rabin_public)
    print("Signature Verified by Bob:", verification)
    if verification:
        # ECDH Verification:
        alice.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, alice.private_key))
        bob.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, bob.private_key))
        alice_read_bob = ECDH.calculate_point(bob.point["x3"], bob.point["y3"], parameters1["a"], random_prime1, alice.private_key)
        bob_read_alice = ECDH.calculate_point(alice.point["x3"], alice.point["y3"], parameters1["a"], random_prime1, bob.private_key)

        if alice_read_bob["x3"] == bob_read_alice["x3"] and alice_read_bob["y3"] == bob_read_alice["y3"]:
            print("PROPERLY IMPLEMENTED DIFFIE-HELLMAN PROTOCOL")
            print("Alice Sends Bob an encrypted text:")
            # SALSA20 CFB Encryption / Decryption:
            # Key derivation from ECDH result
            alice.salsa_key = alice_read_bob["x3"].to_bytes(32, byteorder='big')
            bob.salsa_key = bob_read_alice["x3"].to_bytes(32, byteorder='big')

            alice_encrypted = salsa20_CFB.salsa20_cfb_encrypt(alice.salsa_key, alice.iv, alice.plainText)
            print("Encrypted:", alice_encrypted)
            bob_decrypted = salsa20_CFB.salsa20_cfb_decrypt(bob.salsa_key, bob.iv, alice_encrypted)
            print("Decrypted:", bob_decrypted)

        

main()
