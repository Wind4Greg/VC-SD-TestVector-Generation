# Salted Hash of Claims (SHoC): post-quantum SD cryptosuites

Step-by-step generation of the selective disclosure test vectors for `mldsa44-sd-2024`, `slhdsa128-sd-2024` and `falcon512-sd-2024` in [VC-DI-Quantum-Resistant](https://github.com/w3c/vc-di-quantum-resistant). The SHoC algorithms themselves are in [VC-Data-Integrity](https://w3c.github.io/vc-data-integrity/).

Post-quantum signatures are long, so signing each claim individually (as SIC does) would make proofs very large. Instead, SHoC salts and hashes each non-mandatory N-Quad, and these salted hashes become the leaves of a Merkle tree. The issuer makes a single signature over the proof configuration hash, the mandatory hash, the number of leaves and the Merkle root.

The base proof carries a salt seed rather than the salts. The holder derives every salt from the seed, and the derived proof carries:

* the salts of the disclosed claims only;
* a *subtree proof*: the roots of the largest subtrees that contain no disclosed claims.

The verifier hashes each disclosed claim with its salt, rebuilds the Merkle root from those leaf hashes and the subtree proof, and checks the signature. The salt seed never reaches the verifier, since it would reveal the salts of the undisclosed claims.

Run all steps with `npm run gen:shoc`, or run them individually in this order. Only the `employ` example is generated so far.

| Step | Script | Reads | Writes |
|:--|:--|:--|:--|
| 1. Add base proof | [AddBaseSteps.js](AddBaseSteps.js) | unsigned credential, mandatory pointers, [HMACKey.json](../input/HMACKey.json), [SaltSeed.json](../input/SaltSeed.json), `Keys{MLDSA,SLHDSA,FALCON}.json` | Shared by all three suites, in `output/common/<example>/`: `addBaseTransform.json`, `addSalts.json`, `addMerkleData.json`. Per suite, in `output/<suite>/<example>/`: `addProofConfig.json`, `addProofConfigCanon.txt`, `addHashData.json`, `addSignedSDBase.json` |
| 2. Derive proof | [DeriveSteps.js](DeriveSteps.js) | `addSignedSDBase.json`, selective pointers | per suite: `derivedRecoveredBaseData.json`, `derivedUnsignedReveal.json`, `derivedGroupIndexes.json`, `derivedSubtreeProof.json`, `derivedDisclosureData.json`, `derivedRevealDocument.json` |
| 3. Verify base proof | [VerifyBaseSteps.js](VerifyBaseSteps.js) | `addSignedSDBase.json` | (console only) |
| 4. Verify derived proof | [VerifyDeriveSteps.js](VerifyDeriveSteps.js) | `derivedRevealDocument.json` | (console only) |

The transformation, salts, leaf hashes and Merkle root don't depend on the signature algorithm, so they are computed once and live in `output/common/`. Each suite then signs the same root with its own algorithm.

The intermediate files:

* `addSalts.json`: the salt seed and the salts derived from it.
* `addMerkleData.json`: the number of leaves (`treeSize`), every leaf hash, and the Merkle root.
* `addHashData.json`: `proofHash`, `mandatoryHash`, `treeSize`, `merkleRoot`, and `toSign`, the exact bytes signed.
* `derivedSubtreeProof.json`: the disclosed leaf positions and each subtree proof value, labeled with the tree node it is the root of. `N_a_b` covers leaves `a` to `b - 1` and `Leafj` is leaf `j`, the naming used in the spec and in [SimpleMerkle](https://github.com/Wind4Greg/SimpleMerkle).

Base proof verification (step 3) is a holder-side check, since the spec defines no base proof verification. The holder rebuilds the Merkle root from the salt seed and the document, then checks the signature.

## Algorithms

| File | Spec sections |
|:--|:--|
| [merkle.js](merkle.js) | [MTH](https://w3c.github.io/vc-data-integrity/#MTH), [ComputeTreeShape](https://w3c.github.io/vc-data-integrity/#ComputeTreeShape), [CreateSubtreeProof](https://w3c.github.io/vc-data-integrity/#CreateSubtreeProof), [VerifySubtreeProof](https://w3c.github.io/vc-data-integrity/#VerifySubtreeProof) |
| [salts.js](salts.js) | [DeriveSaltsSD](https://w3c.github.io/vc-data-integrity/#DeriveSaltsSD): `salts[i]` is the first 16 bytes of `HMAC-SHA-256(saltSeed, uint64be(i))` |
| [proofValue.js](proofValue.js) | [SerializeBase-SHoC](https://w3c.github.io/vc-data-integrity/#SerializeBase-SHoC), [ParseBase-SHoC](https://w3c.github.io/vc-data-integrity/#ParseBase-SHoC), [SerializeDerived-SHoC](https://w3c.github.io/vc-data-integrity/#SerializeDerived-SHoC), [ParseDerived-SHoC](https://w3c.github.io/vc-data-integrity/#ParseDerived-SHoC) |

[merkle.js](merkle.js) is written from the spec text, and verification is sparse, as the spec requires: it never builds a tree of `treeSize` nodes. Two check scripts test these files:

* `npm run check:merkle` ([tools/merkleCheck.js](../tools/merkleCheck.js)) compares `merkle.js` against a local checkout of [SimpleMerkle](https://github.com/Wind4Greg/SimpleMerkle) over about ten thousand tree sizes and disclosure sets. It also checks the spec's examples and invariants, the empty and single-leaf trees, and malformed proofs. By default it looks for SimpleMerkle in `../SelectiveDisclosure/SimpleMerkle` beside this repo; use `--simple-merkle <dir>` to point elsewhere. Without SimpleMerkle the comparison is skipped and the other checks still run.
* `npm run check:shoc` ([tools/shocCheck.js](../tools/shocCheck.js)) checks the salt derivation against Node's own HMAC, round-trips both proof values, and checks that malformed proof values are rejected.

## Proof values

| Proof | Header bytes | CBOR components |
|:--|:--|:--|
| base | `0xd9 0x5d 0x12` | signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers |
| derived | `0xd9 0x5d 0x13` | signature, treeSize, leafIndexes, filteredSalts (disclosed claims only), subtreeProof, compressedLabelMap, mandatoryIndexes |

The signed data is `toSign = proofHash || mandatoryHash || uint64be(treeSize) || merkleRoot`, signed as is (not hashed first). The salt seed is not signed; the salts are bound to the root through the leaf hashes. `treeSize` must be signed because the root alone doesn't fix it (see [SPEC_ISSUES.md](SPEC_ISSUES.md) #2).

A leaf hash is `SHA-256(0x00 || salt || statement)` and an internal node is `SHA-256(0x01 || left || right)`. SHoC uses the shuffled blank node label map, so the compressed label map maps integers to integers.

The spec calls the header bytes tentative. The earlier SHoC proofs (headers `0x10` / `0x11`, carrying every salt and salted hash) are no longer generated.

## Reproducibility

The salt seed comes from [input/SaltSeed.json](../input/SaltSeed.json), so regenerating gives byte-identical files for all three suites. Signing passes `extraEntropy: false`, which makes ML-DSA and SLH-DSA signing deterministic, and the Falcon signatures here have also come out identical across runs. Real proofs must use a fresh random salt seed, as the spec requires.

## Specification issues

Issues found while implementing the SHoC algorithms are recorded in [SPEC_ISSUES.md](SPEC_ISSUES.md).
