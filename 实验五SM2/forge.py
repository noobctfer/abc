from gmssl import sm2, func

# Step 1: 生成攻击者私钥
attacker_private_key = func.random_hex(64)  # 32字节 = 64 hex字符
print("私钥（攻击者）:", attacker_private_key)

# Step 2: 计算对应公钥（椭圆曲线乘法）
temp_sm2 = sm2.CryptSM2(private_key=attacker_private_key, public_key="00")  # 临时给个非None
satoshi_public_key = temp_sm2._kg(int(attacker_private_key, 16), temp_sm2.ecc_table['g'])
print("公钥（伪装为中本聪）:", satoshi_public_key)

# Step 3: 用攻击者密钥对初始化 sm2 对象
sm2_attacker = sm2.CryptSM2(private_key=attacker_private_key, public_key=satoshi_public_key)

# Step 4: 签名伪造消息
msg = b"Satoshi is alive!"
k = func.random_hex(sm2_attacker.para_len)
fake_signature = sm2_attacker.sign(msg, k)
print("伪造签名:", fake_signature)

# Step 5: 模拟验证者，使用伪造公钥验证签名
sm2_verifier = sm2.CryptSM2(public_key=satoshi_public_key, private_key=None)
is_valid = sm2_verifier.verify(fake_signature, msg)
print("验签结果（误认为是中本聪签的）:", is_valid)
