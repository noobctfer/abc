# generate_poseidon2_constants.py

from hashlib import sha256

# 使用标准 prime: BN254
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def lfsr(seed_bytes: bytes, n_outputs: int):
    """基于 Poseidon2 LFSR（SHA256）生成字段元素"""
    state = seed_bytes
    results = []
    while len(results) < n_outputs:
        state = sha256(state).digest()
        val = int.from_bytes(state, 'big') % p
        results.append(val)
    return results

def generate_constants(t, full_rounds, partial_rounds):
    R_F = full_rounds
    R_P = partial_rounds
    total_rounds = R_F + R_P
    num_consts = total_rounds * t
    rc = lfsr(b"poseidon2_constants", num_consts)

    print("template RoundConstants() {")
    print(f"    signal output C[{total_rounds}][{t}];")
    for i in range(total_rounds):
        row = rc[i*t:(i+1)*t]
        for j in range(t):
            print(f"    C[{i}][{j}] <-- {row[j]};")
    print("}")

def generate_mds(t):
    mat = []
    for i in range(t):
        row = lfsr(b"poseidon2_mds_" + bytes([i]), t)
        mat.append(row)

    print("template MDS" + str(t) + "() {")
    print(f"    signal input in[{t}];")
    print(f"    signal output out[{t}];")

    for i in range(t):
        print(f"    out[{i}] <== 0;")
        for j in range(t):
            print(f"    out[{i}] <== out[{i}] + in[{j}] * {mat[i][j]};")
    print("}")
    

if __name__ == "__main__":
    print("// === Poseidon2 Constants ===")
    generate_constants(t=3, full_rounds=8, partial_rounds=0)  # 举例：8轮，全full轮
    print()
    print("// === Poseidon2 MDS Matrix ===")
    generate_mds(t=3)
