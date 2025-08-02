from gmssl import sm3, func
import os
import random

# SM2参数
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

def mod_inv(x, m=n):
    return pow(x, -1, m)

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

def sm3_hash(data: bytes) -> bytes:
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))

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

def sm2_sign(msg: bytes, d: int, user_id=b'1234567812345678'):
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
        return (r, s), k

def sm2_verify(msg: bytes, signature, Px, Py, user_id=b'1234567812345678'):
    r, s = signature
    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False
    za = ZA(user_id, Px, Py)
    e = int.from_bytes(sm3_hash(za + msg), 'big')
    t = (r + s) % n
    if t == 0:
        return False
    xy = point_add(
        point_mul(s, (Gx, Gy)),
        point_mul(t, (Px, Py))
    )
    if xy is None:
        return False
    R = (e + xy[0]) % n
    return R == r

# ==== 攻击与私钥恢复 ====

# 1. 已知 k 泄露恢复私钥
def recover_privkey_from_k(r, s, k):
    numerator = (k - s) % n
    denominator = (s + r) % n
    d = (numerator * mod_inv(denominator)) % n
    return d

# 2. 两条签名使用相同k恢复私钥
def recover_privkey_from_two_signatures(r1, s1, r2, s2):
    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r1 - r2) % n
    d = (numerator * mod_inv(denominator)) % n
    return d

# 3. 跨用户重复k恢复私钥
def recover_privkeys_cross_user(r1, s1, r2, s2, k):
    dA = ((k - s1) * mod_inv(s1 + r1)) % n
    dB = ((k - s2) * mod_inv(s2 + r2)) % n
    return dA, dB

# 4. ECDSA 与 SM2 使用同一 d,k 恢复私钥
def recover_privkey_ecdsa_sm2(r1, s1, r2, s2, e1):
    numerator = (s1 * s2 - e1) % n
    denominator = (r1 - s1 * r2) % n
    d = (numerator * mod_inv(denominator)) % n
    return d

def verify_recovered_privkey(d, msg, signature, user_id=b'1234567812345678'):
    Px, Py = point_mul(d, (Gx, Gy))
    return sm2_verify(msg, signature, Px, Py, user_id)

# ==== 测试完整流程 ====

if __name__ == "__main__":
    user_id = b'1234567812345678'
    msg = b"Hello, SM2 attack demo!"

    print("----- 生成密钥对与签名 -----")
    d = int.from_bytes(os.urandom(32), 'big') % n
    Px, Py = point_mul(d, (Gx, Gy))
    print(f"私钥 d = {hex(d)}")
    print(f"公钥 Px = {hex(Px)}\nPy = {hex(Py)}")

    # 1. 正常签名
    (r, s), k = sm2_sign(msg, d, user_id)
    print(f"签名: r = {hex(r)}, s = {hex(s)}")
    assert sm2_verify(msg, (r, s), Px, Py, user_id), "正常验签失败"

    print("\n----- 1. k 泄露攻击 -----")
    d_rec = recover_privkey_from_k(r, s, k)
    print("恢复私钥:", hex(d_rec))
    print("验证恢复私钥有效性:", verify_recovered_privkey(d_rec, msg, (r, s), user_id))

    print("\n----- 2. 两条签名复用 k 攻击 -----")
    # 生成第二条使用相同k的签名
    msg2 = b"Another message"
    e = int.from_bytes(sm3_hash(ZA(user_id, Px, Py) + msg2), 'big')
    x1, y1 = point_mul(k, (Gx, Gy))
    r2 = (e + x1) % n
    s2 = (mod_inv(1 + d, n) * (k - r2 * d)) % n
    assert r2 != 0 and s2 != 0
    sig2 = (r2, s2)
    print(f"第二条签名: r2={hex(r2)}, s2={hex(s2)}")
    d_rec2 = recover_privkey_from_two_signatures(r, s, r2, s2)
    print("恢复私钥:", hex(d_rec2))
    print("验证第一条签名:", verify_recovered_privkey(d_rec2, msg, (r, s), user_id))
    print("验证第二条签名:", verify_recovered_privkey(d_rec2, msg2, sig2, user_id))

    print("\n----- 3. 跨用户重复k攻击 -----")
    # 生成另一用户私钥和用同一k签名
    d_b = int.from_bytes(os.urandom(32), 'big') % n
    Px_b, Py_b = point_mul(d_b, (Gx, Gy))
    (r_b, s_b), _ = sm2_sign(b"Bob's message", d_b, user_id)
    # 用泄露的k强制签名第二用户，构造恶意签名以模拟同k
    # 这里直接用k重新签一次方便演示
    msg_b = b"Bob's message"
    e_b = int.from_bytes(sm3_hash(ZA(user_id, Px_b, Py_b) + msg_b), 'big')
    r_b = (e_b + point_mul(k, (Gx, Gy))[0]) % n
    s_b = (mod_inv(1 + d_b, n) * (k - r_b * d_b)) % n
    sig_b = (r_b, s_b)
    dA_rec, dB_rec = recover_privkeys_cross_user(r, s, r_b, s_b, k)
    print("恢复 Alice 私钥:", hex(dA_rec))
    print("恢复 Bob 私钥:", hex(dB_rec))
    print("验证 Alice 签名:", verify_recovered_privkey(dA_rec, msg, (r, s), user_id))
    print("验证 Bob 签名:", verify_recovered_privkey(dB_rec, msg_b, sig_b, user_id))

    print("\n----- 4. ECDSA 和 SM2 共用 d,k 攻击 -----")
    # ECDSA 签名简化版本模拟 (不是完整ECDSA代码，只模拟输出r,s)
    # 注意e1是消息哈希
    msg_ecdsa = b"ECDSA message"
    e1 = int.from_bytes(sm3_hash(msg_ecdsa), 'big')
    # ECDSA签名
    x1, y1 = point_mul(k, (Gx, Gy))
    r_ecdsa = x1 % n
    s_ecdsa = (mod_inv(k, n) * (e1 + d * r_ecdsa)) % n
    # SM2签名使用相同d,k
    za = ZA(user_id, Px, Py)
    e2 = int.from_bytes(sm3_hash(za + msg), 'big')
    r_sm2 = (e2 + x1) % n
    s_sm2 = (mod_inv(1 + d, n) * (k - r_sm2 * d)) % n
    d_rec4 = recover_privkey_ecdsa_sm2(r_ecdsa, s_ecdsa, r_sm2, s_sm2, e1)
    print("恢复私钥:", hex(d_rec4))
    print("验证 SM2 签名:", verify_recovered_privkey(d_rec4, msg, (r_sm2, s_sm2), user_id))
