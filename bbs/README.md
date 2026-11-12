# BBS: `bbs-2023` and its optional features

Step-by-step generation of the selective disclosure test vectors for [VC-DI-BBS](https://github.com/w3c/vc-di-bbs).

BBS provides selective disclosure at the cryptographic layer. The issuer signs all the non-mandatory N-Quads as BBS *messages* in one signature. The BBS *header* is the concatenation of `proofHash` and `mandatoryHash`. The holder derives an unlinkable BBS proof that reveals only the selected messages. BBS uses the shuffled blank node label map, so that the labels themselves don't make derived proofs linkable.

Run everything with `npm run gen:bbs`. Each feature has its own folder, and its scripts run in the order listed:

| Folder | Feature | Examples | Steps |
|:--|:--|:--|:--|
| [Baseline/](Baseline/) | baseline | `wind`, `prc` (`--example` supported) | AddBaseSteps, DeriveSteps, VerifyBaseSteps, VerifyDeriveSteps |
| [HolderBinding/](HolderBinding/) | anonymous holder binding | `license` | CreateCommitment, AddBaseSteps, VerifyBaseSteps, DeriveSteps, VerifyDeriveSteps |
| [Pseudonym/](Pseudonym/) | pseudonym, hidden PID | `license` | same as HolderBinding |
| [PseudonymHB/](PseudonymHB/) | pseudonym with holder binding | `license` | same as HolderBinding |

Outputs go to `output/<feature>/<example>/`. For the features, `CreateCommitment.js` produces the holder's commitment (`commitmentInfo.json`), which the issuer then blind signs. The `Pseudonym` and `PseudonymHB` derive steps also write `nymSecret.json`.

Inputs (in [../input/](../input/)):

* **Key material:** `BBSKeyMaterial.json`.
* **Derived-proof options:** `BBSDeriveMaterial.json`, which holds the presentation header and the seed for the baseline proof's pseudo-random scalars.
* **Holder binding:** `holderSecret.json`.
* **Pseudonyms:** `proverNym.json`, `signerNymEntropy.json` and `verifierInfo.json`.

The BBS primitives (signing, proofs, blind signatures and pseudonyms) are in [lib/](lib/). `testScalars.js` writes sample random scalars to `bbs/temp/` (git-ignored).

## Determinism

The baseline outputs are deterministic, because the baseline derived proof uses seeded pseudo-random scalars. The holder binding and pseudonym features use fresh randomness, for the commitments and the proofs, so their outputs change on every run. Use `npm test` to check that the committed ones verify.

## Proof value formats

[proofValue.js](proofValue.js) implements serialize and parse for the base and derived proof values. Its `featureOption` parameter selects the feature. This table shows what the scripts here generate:

| Feature | Proof | Header bytes | CBOR components | api_id | Extra inputs |
|:--|:--|:--|:--|:--|:--|
| baseline | base | `0xd9 0x5d 0x02` | bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers | BBS-SHA | none |
| baseline | derived | `0xd9 0x5d 0x03` | bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader | BBS-SHA | none |
| anonymous holder binding | base | `0xd9 0x5d 0x04` | bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers | BLIND-BBS | commitment with proof for the holder secret |
| anonymous holder binding | derived | `0xd9 0x5d 0x05` | bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader, lengthBBSMessages | BLIND-BBS | holder secret, prover blind |
| pseudonym (hidden PID) | base | `0xd9 0x5d 0x08` | bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers, signerNymEntropy | PSEUDONYM-BBS | commitment with proof for the prover nym |
| pseudonym (hidden PID) | derived | `0xd9 0x5d 0x09` | bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader, pseudonym, lengthBBSMessages | PSEUDONYM-BBS | prover nym, prover blind, verifier id |
| pseudonym with holder binding | base | `0xd9 0x5d 0x08` | as pseudonym | PSEUDONYM-BBS | commitment to the holder secret and prover nym |
| pseudonym with holder binding | derived | `0xd9 0x5d 0x09` | as pseudonym | PSEUDONYM-BBS | holder secret, prover nym, prover blind, verifier id |

Earlier notes also described a pseudonym variant with an *issuer-known* PID, using header bytes `0xd9 0x5d 0x06` (base) and `0x07` (derived). No script here generates that variant.

**Open question:** "pseudonym with holder binding" currently reuses the hidden-PID header bytes `0x08`/`0x09`. If the spec gives it its own header bytes, change them in the `FEATURES` table in [proofValue.js](proofValue.js) and regenerate.
