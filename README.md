# ma-heuer

Jonah Heuer: Master's thesis - "Meet-in-the-Middle Attacks on Sponge Functions"

## Goal
Implement the MitM attack on the SPHINCS+-Haraka sponge construction. 

## This repository
`attack/`: Contains the code for the MitM attack on the 4-round Haraka sponge as
described by Dong et al.

`haraka/`: Simple and unsafe implementation of full 5-round Haraka and associated sponge,
for demonstration and testing purposes.

## References

- Dong et al. Generic MitM Attack Frameworks on Sponge Constructions.
https://eprint.iacr.org/2024/604.pdf
- Qin et al. Meet-in-the-Middle Preimage Attacks on Sponge-based Hashing.
https://eprint.iacr.org/2022/1714.pdf
- SPHINCS+ - Submission to the 3rd round of the NIST post-quantum project, v3.1.
https://sphincs.org/data/sphincs+-r3.1-specification.pdf
- Kölbl et al. Haraka v2 - Efficient Short-Input Hashing for Post-Quantum Applications.
https://eprint.iacr.org/2016/098.pdf
