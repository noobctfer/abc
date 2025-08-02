from gmssl import sm3, func
import random

# --- SM3 哈希，调用库的纯哈希接口 ---
def sm3_hash(data: bytes) -> bytes:
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))

# --- 椭圆曲线参数 (国密 SM2 标准参数) ---
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# --- 椭圆曲线点加法和倍加 ---
def mod_inv(x, p=p):
    # Python 3.8+ 支持 pow(x, -1, p)
    return pow(x, -1, p)

def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P == Q:
        return point_double(P)
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None

    lam = ((Q[1] - P[1]) * mod_inv(Q[0] - P[0], p)) % p
    x_r = (lam * lam - P[0] - Q[0]) % p
    y_r = (lam * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

def point_double(P):
    if P is None:
        return None
    lam = ((3 * P[0] * P[0] + a) * mod_inv(2 * P[1], p)) % p
    x_r = (lam * lam - 2 * P[0]) % p
    y_r = (lam * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

def point_mul(k, P):
    R = None
    N = P
    while k > 0:
        if k & 1:
            R = point_add(R, N)
        N = point_double(N)
        k >>= 1
    return R

# --- ZA 计算 (带用户ID的哈希输入) ---
def ZA(user_id: bytes, Px, Py):
    ENTLA = len(user_id)*8
    entla_bytes = ENTLA.to_bytes(2, byteorder='big')
    a_bytes = a.to_bytes(32, byteorder='big')
    b_bytes = b.to_bytes(32, byteorder='big')
    gx_bytes = Gx.to_bytes(32, byteorder='big')
    gy_bytes = Gy.to_bytes(32, byteorder='big')
    px_bytes = Px.to_bytes(32, byteorder='big')
    py_bytes = Py.to_bytes(32, byteorder='big')

    data = entla_bytes + user_id + a_bytes + b_bytes + gx_bytes + gy_bytes + px_bytes + py_bytes
    return sm3_hash(data)

# --- 签名 ---
def sm2_sign(msg: bytes, d: int, user_id: bytes = b'1234567812345678'):
    Px, Py = point_mul(d, (Gx, Gy))
    za = ZA(user_id, Px, Py)
    e = int.from_bytes(sm3_hash(za + msg), 'big')

    while True:
        k = random.randrange(1, n)
        x1, y1 = point_mul(k, (Gx, Gy))
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (mod_inv(1 + d, n) * (k - r * d)) % n
        if s == 0:
            continue
        return (r, s)

# --- 验签 ---
def sm2_verify(msg: bytes, signature, Px, Py, user_id: bytes = b'1234567812345678'):
    r, s = signature
    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False
    za = ZA(user_id, Px, Py)
    e = int.from_bytes(sm3_hash(za + msg), 'big')

    t = (r + s) % n
    if t == 0:
        return False
    x1, y1 = point_add(
        point_mul(s, (Gx, Gy)),
        point_mul(t, (Px, Py))
    )
    R = (e + x1) % n
    return R == r

# --- 简单测试 ---
if __name__ == "__main__":
    import os

    d = int.from_bytes(os.urandom(32), 'big') % n
    Px, Py = point_mul(d, (Gx, Gy))
    msg = b"test sm2 with library for hash only"
    signature = sm2_sign(msg, d)
    print("Signature:", signature)
    result = sm2_verify(msg, signature, Px, Py)
    print("Verify result:", result)
