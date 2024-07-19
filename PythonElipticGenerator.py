import random
import os
from Crypto.Util import number

PRIME_NUMBER_SIZE = 256

def draw_prime_number():
    pr = number.getPrime(PRIME_NUMBER_SIZE, os.urandom)
    if pr % 4 != 3:
        return draw_prime_number()
    return pr

def is_delta_valid(a, b, p):
    return (4 * a**3 + 27 * b**2) % p != 0

def calculate_f(a, b, x, p):
    return int((x ** 3 + a * x + b)) % p

def check_legendre(f, p):
    base = (p - 1) // 2
    mod = pow(f, base, p)
    return mod == 1

def calculate_y(f, p):
    powing = (p + 1) // 4
    y = pow(f, powing, p)
    return y

def test_equality(y, p, x, a, b):
    y_squared = pow(y, 2, p)
    f_test = (pow(x, 3) + a * x + b) % p
    return y_squared == f_test

def draw_parameters(random_prime):
    a = random.randrange(2, random_prime-1)
    b = random.randrange(2, random_prime-1)

    if not is_delta_valid(a, b, random_prime):
        return draw_parameters(random_prime)
    x = random.randrange(2, random_prime-1)
    f = calculate_f(a, b, x, random_prime)
    if not check_legendre(f, random_prime):
        return draw_parameters(random_prime)
    y = calculate_y(f, random_prime)

    if not test_equality(y, random_prime, x, a, b):
        return draw_parameters(random_prime)

    print("POINT P - x: " + str(x) + " y: " + str(y) + " is on the curve")
    return {'a': a, 'b': b, 'x': x, 'y': y}

def add_points(x1, y1, x2, y2, a, p):
    #case 1
    if x1 != x2:
        up = (y2 - y1) % p
        down = (x2 - x1) % p
        if down == 0:
            return {"x3": 0, "y3": 0}
        m = (up * pow(down, -1, p)) % p
        x3 = (pow(m, 2) - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return {"x3": x3, "y3": y3}
    elif x1 == x2 and y1 != y2:
        return {"x3": 0, "y3": 0}
    elif x1 == x2 and y1 == y2 and y1 != 0:
        up = (3 * pow(x1, 2) + a) % p
        down = (2 * y1) % p
        if down == 0:
            return {"x3": 0, "y3": 0}
        m = (up * pow(down, -1, p)) % p
        x3 = (pow(m, 2) - 2 * x1) % p
        y3 = (m * (x1 - x3) - y1) % p
        return {"x3": x3, "y3": y3}
    elif x1 == x2 and y1 == y2 and y2 == 0:
        return {"x3": 0, "y3": 0}
    elif x1 == 0 and y1 == 0:
        return {"x3": x2, "y3": y2}
    elif x2 == 0 and y2 == 0:
        return {"x3": x1, "y3": y1}

def calculate_point(x1, y1, a, p, n):

    init_point = {"x1": x1, "y1": y1}
    result_point = {"x3": x1, "y3": y1}
    i = 0
    while i < n:
        result_point = add_points(result_point["x3"], result_point["y3"], init_point["x1"], init_point["y1"], a, p)
        i += 1

    return result_point

def test_point(r, parameters, p):
    # y2 = x3 + ax + b
    right = calculate_f(parameters["a"], parameters["b"], r["x3"], p)
    left = (r["y3"]**2) % p

    return left == right

def main():
    # First interaction (Alice and Bob)
    random_prime1 = draw_prime_number()
    print(random_prime1, "DRAWN RANDOM PRIME 1")
    parameters1 = draw_parameters(random_prime1)

    print(parameters1['a'], "a")
    print(parameters1['b'], "b")

    n1 = 336668
    n2 = 444466

    point_alice = calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, n1)
    point_bob = calculate_point(parameters1['x'], parameters1['y'], parameters1['a'], random_prime1, n2)

    print("ALICE POINT: ", point_alice)
    print("BOB POINT: ", point_bob)

    re1 = test_point(point_alice, parameters1, random_prime1)
    re2 = test_point(point_bob, parameters1, random_prime1)
    print(re1)
    print(re2)

    alice_read_bob = calculate_point(point_bob["x3"], point_bob["y3"], parameters1["a"], random_prime1, n1)
    bob_read_alice = calculate_point(point_alice["x3"], point_alice["y3"], parameters1["a"], random_prime1, n2)

    print("ALICE READ BOB: ", alice_read_bob)
    print("BOB READ ALICE: ", bob_read_alice)

    if alice_read_bob["x3"] == bob_read_alice["x3"] and alice_read_bob["y3"] == bob_read_alice["y3"]:
        print("PROPERLY IMPLEMENTED DIFFIE-HELLMAN PROTOCOL RUN 1")

    # Second interaction (Bob and Eve)
    random_prime2 = draw_prime_number()
    print(random_prime2, "DRAWN RANDOM PRIME 2")
    parameters2 = draw_parameters(random_prime2)

    print(parameters2['a'], "a")
    print(parameters2['b'], "b")

    n2 = 444466
    n3 = 555577

    point_eve = calculate_point(parameters2['x'], parameters2['y'], parameters2['a'], random_prime2, n3)
    point_bob = calculate_point(parameters2['x'], parameters2['y'], parameters2['a'], random_prime2, n2)

    print("EVE POINT: ", point_eve)
    print("BOB POINT: ", point_bob)

    re3 = test_point(point_eve, parameters2, random_prime2)
    re2 = test_point(point_bob, parameters2, random_prime2)
    print(re3)
    print(re2)

    eve_read_bob = calculate_point(point_bob["x3"], point_bob["y3"], parameters2["a"], random_prime2, n3)
    bob_read_eve = calculate_point(point_eve["x3"], point_eve["y3"], parameters2["a"], random_prime2, n2)

    print("EVE READ BOB: ", eve_read_bob)
    print("BOB READ EVE: ", bob_read_eve)

    if eve_read_bob["x3"] == bob_read_eve["x3"] and eve_read_bob["y3"] == bob_read_eve["y3"]:
        print("PROPERLY IMPLEMENTED DIFFIE-HELLMAN PROTOCOL RUN 2")

# execute program
main()
