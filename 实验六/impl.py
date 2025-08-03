import random
from hashlib import sha256
from phe import paillier
def randomize(pk, ciphertext):
    random_enc_zero = pk.encrypt(0)
    return ciphertext + random_enc_zero
# ---------------------------------
# 模拟一个大素数阶群G的运算（这里简化为模大素数的乘法群）
# ---------------------------------
class GroupG:
    def __init__(self, p):
        self.p = p
        self.q = p - 1  # 方便起见，假设群阶q=p-1

    def random_exp(self):
        return random.randint(1, self.q - 1)

    def hash_to_group(self, identifier: str):
        # H: U->G，哈希到群元素
        h = int(sha256(identifier.encode()).hexdigest(), 16)
        return pow(h, 1, self.p)

    def exp(self, base, exponent):
        # 群运算幂
        return pow(base, exponent, self.p)

# ---------------------------------
# Party 1
# ---------------------------------
class Party1:
    def __init__(self, group: GroupG, V):
        self.group = group
        self.V = V  # 输入集合
        self.k1 = group.random_exp()  # 私钥

    def round1(self):
        # H(v_i)^k1
        self.v_hashes = [self.group.hash_to_group(v) for v in self.V]
        self.v_k1 = [self.group.exp(hv, self.k1) for hv in self.v_hashes]
        # 打乱顺序模拟隐私
        random.shuffle(self.v_k1)
        return self.v_k1

    def round3(self, Hwk2_AEnc_tj, Z, pk):
        # 对收到的(H(w_j)^k2, Enc(t_j))，第一项做k1次幂，检查是否在Z中
        intersection_enc = []
        for (hwj_k2, enc_tj) in Hwk2_AEnc_tj:
            hwj_k1k2 = self.group.exp(hwj_k2, self.k1)
            if hwj_k1k2 in Z:
                intersection_enc.append(enc_tj)

        # 同态加密加总
        if not intersection_enc:
            # 若交集为空，返回加密0
            sum_cipher = pk.encrypt(0)
        else:
            sum_cipher = intersection_enc[0]
            for ct in intersection_enc[1:]:
                sum_cipher += ct

        # 随机化加密防止重放
        sum_cipher = randomize(pk, sum_cipher)
        return sum_cipher

# ---------------------------------
# Party 2
# ---------------------------------
class Party2:
    def __init__(self, group: GroupG, W):
        self.group = group
        self.W = W  # 带权集合 (w_j, t_j)
        self.k2 = group.random_exp()  # 私钥
        self.pk, self.sk = paillier.generate_paillier_keypair()

    def round2(self, v_k1_list):
        # 计算 Z = { H(v_i)^{k1 k2} }
        Z = [self.group.exp(vk1, self.k2) for vk1 in v_k1_list]
        random.shuffle(Z)

        # 计算 S = {(H(w_j)^k2, Enc(t_j))}
        Hwk2_AEnc_tj = []
        for (wj, tj) in self.W:
            hwj = self.group.hash_to_group(wj)
            hwj_k2 = self.group.exp(hwj, self.k2)
            enc_tj = self.pk.encrypt(tj)
            Hwk2_AEnc_tj.append((hwj_k2, enc_tj))
        random.shuffle(Hwk2_AEnc_tj)

        return Z, Hwk2_AEnc_tj, self.pk

    def decrypt_result(self, ciphertext):
        return self.sk.decrypt(ciphertext)

# ---------------------------------
# 模拟执行协议
# ---------------------------------
def demo():
    p = 2**127 - 1
    group = GroupG(p)

    # P1 输入集合V
    V = ['alice@example.com', 'bob@example.com', 'carol@example.com']

    # P2 输入带权集合W
    W = [('dave@example.com', 5), ('carol@example.com', 10), ('alice@example.com', 3)]

    p1 = Party1(group, V)
    p2 = Party2(group, W)

    # Round 1: P1 -> P2
    v_k1_list = p1.round1()

    # Round 2: P2 -> P1
    Z, Hwk2_AEnc_tj, pk = p2.round2(v_k1_list)

    # Round 3: P1 -> P2
    sum_cipher = p1.round3(Hwk2_AEnc_tj, Z, pk)

    # Output: P2 解密
    intersection_sum = p2.decrypt_result(sum_cipher)
    print(f"Intersection sum is: {intersection_sum}")

if __name__ == "__main__":
    demo()
