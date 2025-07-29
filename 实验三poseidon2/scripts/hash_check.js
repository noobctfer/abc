const poseidon = require("circomlibjs").poseidon;
const F = require("circomlibjs").buildBabyjub();

async function main() {
    const inputs = [123n, 456n];
    const hash = poseidon(inputs);
    console.log("Poseidon2 hash:", F.toObject(hash));
}
main();
