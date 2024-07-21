import ElipticCurveGenerator as ECDH
from user import user
from os import urandom
import salsa20_CFB


def main():

    # Parameters Prep    
    random_prime1 = ECDH.draw_prime_number()
    parameters1 = ECDH.draw_parameters(random_prime1)
    n1 = 336668
    n2 = 444466
    # key = urandom(32)  # Salsa20 requires a 32-byte key
    iv = urandom(16)    # Salsa20 nonce is 8 bytes ###### This should be unique for each message ########

    # Users creation:
    alice = user("alice")
    alice.set_pKey(n1)
    # alice.set_salsa_key(key)
    alice.set_iv(iv)

    bob = user("bob")
    bob.set_pKey(n2)
    # bob.set_salsa_key(key)
    bob.set_iv(iv)

    # ECDH Verification:
    alice.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, alice.private_key))
    bob.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, bob.private_key))
    # re1 = ECDH.test_point(alice.point, parameters1, random_prime1)
    # re2 = ECDH.test_point(bob.point, parameters1, random_prime1)
    alice_read_bob = ECDH.calculate_point(bob.point["x3"], bob.point["y3"], parameters1["a"], random_prime1, alice.private_key)
    bob_read_alice = ECDH.calculate_point(alice.point["x3"], alice.point["y3"], parameters1["a"], random_prime1, bob.private_key)

    if alice_read_bob["x3"] == bob_read_alice["x3"] and alice_read_bob["y3"] == bob_read_alice["y3"]:
        print("PROPERLY IMPLEMENTED DIFFIE-HELLMAN PROTOCOL")
        print("Alice Sends Bob an encrypted text:")
        # SALSA20 CFB Encryption / Decryption    :
        plaintext = b"Hello Bob, this is Alice Sending you A message!"
        
        alice.salsa_key = alice.point["x3"].to_bytes(32, byteorder='big')
        bob.salsa_key = alice.point["x3"].to_bytes(32, byteorder='big')
        # print(alice.point["x3"].bit_length(),alice.salsa_key)
        alice_encrypted = salsa20_CFB.salsa20_cfb_encrypt(alice.salsa_key, alice.iv, plaintext)
        print("Encrypted:", alice_encrypted)
        bob_decrypted = salsa20_CFB.salsa20_cfb_decrypt(bob.salsa_key, bob.iv, alice_encrypted)
        print("Decrypted:", bob_decrypted)

    
    # # Second interaction (Bob and Eve)
    # random_prime2 = ECDH.draw_prime_number()
    # parameters2 = ECDH.draw_parameters(random_prime2)

    # n2 = 444466
    # n3 = 555577

    # point_eve = ECDH.calculate_point(parameters2['x'], parameters2['y'], parameters2['a'], random_prime2, n3)
    # bob.point = ECDH.calculate_point(parameters2['x'], parameters2['y'], parameters2['a'], random_prime2, n2)

    # re3 = ECDH.test_point(point_eve, parameters2, random_prime2)
    # re2 = ECDH.test_point(bob.point, parameters2, random_prime2)

    # eve_read_bob = ECDH.calculate_point(bob.point["x3"], bob.point["y3"], parameters2["a"], random_prime2, n3)
    # bob_read_eve = ECDH.calculate_point(point_eve["x3"], point_eve["y3"], parameters2["a"], random_prime2, n2)

    # if eve_read_bob["x3"] == bob_read_eve["x3"] and eve_read_bob["y3"] == bob_read_eve["y3"]:
    #     print("PROPERLY IMPLEMENTED DIFFIE-HELLMAN PROTOCOL RUN 2")

main()