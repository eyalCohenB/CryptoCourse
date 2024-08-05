import ElipticCurveGenerator as ECDH
from user import user
from os import urandom
import salsa20_CFB
import rabin as Rabin
import binascii

def send_message(sender, receivers):
            print(f"{sender.name} Sends {', '.join([r.name for r in receivers])} an encrypted text:")
            signature = Rabin.sign_rabin(sender.p, sender.q, binascii.hexlify(sender.plainText))
            encrypted = salsa20_CFB.salsa20_cfb_encrypt(sender.salsa_key, sender.iv, sender.plainText)
            print("Encrypted:", encrypted)
            for receiver in receivers:
                decrypted = salsa20_CFB.salsa20_cfb_decrypt(receiver.salsa_key, receiver.iv, encrypted)
                message = decrypted.decode('utf-8')
                hexmessage = binascii.hexlify(message.encode())
                verification = Rabin.verify(sender.rabin_public, hexmessage, signature[0], signature[1])
                print(f"Signature Verified by {receiver.name}: {verification}")
                if verification:
                    print(f"Decrypted by {receiver.name}:", message)

def main():
    # Parameters Prep    
    random_prime1 = ECDH.draw_prime_number()
    parameters1 = ECDH.draw_parameters(random_prime1)
    n1 = 336668
    n2 = 444466
    n3 = 555577
    iv = urandom(64)  # Salsa20 nonce is 16 bytes ###### This should be unique for each message ########

    # Users creation:
    alice = user("alice")
    alice.set_pKey(n1)
    alice.set_iv(iv)
    alice.set_plainText(b"Hello Bob and Carol, this is Alice Sending you A message!")  # should be in Bytes! hence 'b' at start

    bob = user("bob")
    bob.set_pKey(n2)
    bob.set_iv(iv)
    bob.set_plainText(b"Hello Alice and Carol, nice hearing from you!")  # should be in Bytes! hence 'b' at start

    carol = user("carol")  
    carol.set_pKey(n3)
    carol.set_iv(iv)
    carol.set_plainText(b"Hello Alice and Bob, Carol here!")  # should be in Bytes! hence 'b' at start

    # ECDH Key Exchange
    alice.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, alice.private_key))
    bob.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, bob.private_key))
    carol.set_point(ECDH.calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, carol.private_key))

    alice_read_bob = ECDH.calculate_point(bob.point["x3"], bob.point["y3"], parameters1["a"], random_prime1, alice.private_key)
    bob_read_alice = ECDH.calculate_point(alice.point["x3"], alice.point["y3"], parameters1["a"], random_prime1, bob.private_key)

    carol_read_alice = ECDH.calculate_point(alice.point["x3"], alice.point["y3"], parameters1["a"], random_prime1, carol.private_key)
    carol_read_bob = ECDH.calculate_point(bob.point["x3"], bob.point["y3"], parameters1["a"], random_prime1, carol.private_key)

    alice_read_carol = ECDH.calculate_point(carol.point["x3"], carol.point["y3"], parameters1["a"], random_prime1, alice.private_key)
    bob_read_carol = ECDH.calculate_point(carol.point["x3"], carol.point["y3"], parameters1["a"], random_prime1, bob.private_key)

    if (alice_read_bob["x3"] == bob_read_alice["x3"] and alice_read_bob["y3"] == bob_read_alice["y3"] and
        alice_read_carol["x3"] == carol_read_alice["x3"] and alice_read_carol["y3"] == carol_read_alice["y3"] and
        bob_read_carol["x3"] == carol_read_bob["x3"] and bob_read_carol["y3"] == carol_read_bob["y3"]):

        print("Properly implemented ECDH protocol.")

        # Key derivation from ECDH result
        shared_secret = ECDH.calculate_point(alice_read_bob["x3"], alice_read_bob["y3"], parameters1["a"], random_prime1, carol.private_key)
        alice.salsa_key = shared_secret["x3"].to_bytes(64, byteorder='big')
        bob.salsa_key = shared_secret["x3"].to_bytes(64, byteorder='big')
        carol.salsa_key = shared_secret["x3"].to_bytes(64, byteorder='big')

        # Alice sends message to Bob and Carol
        alice.set_plainText(b"Hello Bob and Carol, this is Alice Sending you A message!")  # Update message
        send_message(alice, [bob, carol])
        print()

        # Bob sends message to Alice and Carol
        bob.set_plainText(b"Hello Alice and Carol, nice hearing from you!")  # Update message
        send_message(bob, [alice, carol])
        print()

        # Carol sends message to Alice and Bob
        carol.set_plainText(b"Hello Alice and Bob, Carol here!")  # Update message
        send_message(carol, [alice, bob])
        print()


if __name__ == "__main__":
    main()
