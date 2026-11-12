# Salted Hash of Claims (SHoC): post-quantum SD cryptosuites

Step-by-step generation of the selective disclosure test vectors for `mldsa44-sd-2024`, `slhdsa128-sd-2024` and `falcon512-sd-2024` in [VC-DI-Quantum-Resistant](https://github.com/w3c/vc-di-quantum-resistant).

Post-quantum signatures are long, so signing each claim individually (as SIC does) would make proofs very large. Instead, SHoC salts and hashes each non-mandatory N-Quad. The issuer then makes a single signature over the proof configuration hash, the mandatory hash, and the list of salted hashes. A derived proof carries that signature, all the salted hashes, and the salts of the disclosed claims only. The verifier recomputes the salted hash of each disclosed claim and checks that it is in the signed list.

Run all steps with `npm run gen:shoc`, or run them individually in this order. Only the `employ` example is generated so far.

| Step | Script | Reads | Writes |
|:--|:--|:--|:--|
| 1. Add base proof | [AddBaseSteps.js](AddBaseSteps.js) | unsigned credential, mandatory pointers, [HMACKey.json](../input/HMACKey.json), `Keys{MLDSA,SLHDSA,FALCON}.json` | Shared by all three suites, in `output/common/<example>/`: `addBaseTransform.json`, `addSaltedHashes.json`. Per suite, in `output/<suite>/<example>/`: `addProofConfig.json`, `addProofConfigCanon.txt`, `addHashData.json`, `addSignedSDBase.json` |
| 2. Derive proof | [DeriveSteps.js](DeriveSteps.js) | `addSignedSDBase.json`, selective pointers | per suite: `derivedRecoveredBaseData.json`, `derivedUnsignedReveal.json`, `derivedGroupIndexes.json`, `derivedDisclosureData.json`, `derivedRevealDocument.json` |
| 3. Verify base proof | [VerifyBaseSteps.js](VerifyBaseSteps.js) | `addSignedSDBase.json` | (console only) |
| 4. Verify derived proof | [VerifyDeriveSteps.js](VerifyDeriveSteps.js) | `derivedRevealDocument.json` | (console only) |

The transformation and salted hashes are computed once and shared by the three suites, so they live in `output/common/`. Each suite then signs the same salted hashes with its own algorithm.

## Proof values

[proofValue.js](proofValue.js) implements the serialize and parse functions:

| Proof | Header bytes | CBOR components |
|:--|:--|:--|
| base | `0xd9 0x5d 0x10` | signature, hmacKey, salts, saltedHashes, mandatoryPointers |
| derived | `0xd9 0x5d 0x11` | signature, salts (disclosed claims only), saltedHashes (all), compressedLabelMap, mandatoryIndexes, selectiveIndexes |

The signed data is `sha256(proofHash || mandatoryHash || saltedHashes...)`. The salts are not part of the signed data. SHoC uses the shuffled blank node label map, so the compressed label map maps integers to integers.

The salts are random, so the salted hashes, the signatures and everything derived from them change on every run. Signing passes `extraEntropy: false`, which makes ML-DSA and SLH-DSA signing deterministic; it may have no effect for Falcon.

## To do

The [VC-Data-Integrity](https://github.com/w3c/vc-data-integrity) SHoC approach has been updated with two optimizations. They still need to be implemented here.
