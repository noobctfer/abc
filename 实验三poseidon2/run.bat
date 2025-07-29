# 编译电路
circom circuits/poseidon2.circom --r1cs --wasm --sym -o build

# Trusted setup
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau prepare phase2 pot12_0000.ptau zkeys/pot12_final.ptau
snarkjs groth16 setup build/poseidon2.r1cs zkeys/pot12_final.ptau zkeys/poseidon2_0000.zkey
snarkjs zkey contribute zkeys/poseidon2_0000.zkey zkeys/poseidon2_final.zkey --name="Contributor"
snarkjs zkey export verificationkey zkeys/poseidon2_final.zkey zkeys/verification_key.json
# 生成 witness
node build/poseidon2_js/generate_witness.js build/poseidon2_js/poseidon2.wasm input/input.json proofs/witness.wtns
# 生成证明
snarkjs groth16 prove zkeys/poseidon2_final.zkey proofs/witness.wtns proofs/proof.json proofs/public.json

 #证明
snarkjs groth16 verify zkeys/verification_key.json proofs/public.json proofs/proof.json
