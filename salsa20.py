
def rotate(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def quarterround(y0, y1, y2, y3):
    y1 ^= rotate(y0 + y3, 7)
    y2 ^= rotate(y1 + y0, 9)
    y3 ^= rotate(y2 + y1, 13)
    y0 ^= rotate(y3 + y2, 18)
    return y0, y1, y2, y3

def rowround(y):
    y[0], y[1], y[2], y[3] = quarterround(y[0], y[1], y[2], y[3])
    y[5], y[6], y[7], y[4] = quarterround(y[5], y[6], y[7], y[4])
    y[10], y[11], y[8], y[9] = quarterround(y[10], y[11], y[8], y[9])
    y[15], y[12], y[13], y[14] = quarterround(y[15], y[12], y[13], y[14])
    return y

def columnround(x):
    x[0], x[4], x[8], x[12] = quarterround(x[0], x[4], x[8], x[12])
    x[5], x[9], x[13], x[1] = quarterround(x[5], x[9], x[13], x[1])
    x[10], x[14], x[2], x[6] = quarterround(x[10], x[14], x[2], x[6])
    x[15], x[3], x[7], x[11] = quarterround(x[15], x[3], x[7], x[11])
    return x

def doubleround(x):
    return rowround(columnround(x))

def salsa20_hash(x):
    z = x[:]
    for _ in range(10):
        z = doubleround(z)
    return [(z[i] + x[i]) & 0xffffffff for i in range(16)]

def littleendian(b):
    return b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24)

def littleendian_inv(n):
    return bytes([n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff])

def salsa20_block(key, nonce, block_number):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_expanded = [littleendian(key[i:i+4]) for i in range(0, 32, 4)]
    nonce_expanded = [littleendian(nonce[i:i+4]) for i in range(0, 16, 4)]

    state = constants[:4] + key_expanded[:4] + nonce_expanded[:2] + [block_number & 0xffffffff, (block_number >> 32) & 0xffffffff] + key_expanded[4:]

    output = salsa20_hash(state)
    return b''.join(littleendian_inv(output[i]) for i in range(16))
