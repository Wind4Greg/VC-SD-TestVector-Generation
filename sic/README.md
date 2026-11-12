# Signed Individual Claims (SIC): `ecdsa-sd-2023`

Step-by-step generation of the selective disclosure test vectors for the `ecdsa-sd-2023` cryptosuite in [VC-DI-ECDSA](https://w3c.github.io/vc-di-ecdsa/).

In the SIC approach the issuer signs each non-mandatory N-Quad individually, with a proof-specific P-256 key. The base signature covers the proof configuration hash, the proof-specific public key and the hash of the mandatory N-Quads. A derived proof carries the base signature and the signatures of the disclosed claims only. This approach suits signature algorithms with short signatures.

Run all steps with `npm run gen:sic`, or run them individually in this order (each takes `--example`; the default is all of `wind`, `employ` and `prc`):

| Step | Script | Reads | Writes to `output/ecdsa-sd-2023/<example>/` |
|:--|:--|:--|:--|
| 1. Add base proof | [AddBaseSteps.js](AddBaseSteps.js) | unsigned credential, mandatory pointers, [SDKeyMaterial.json](../input/SDKeyMaterial.json) | `addProofConfig.json`, `addProofConfigCanon.txt`, `addBaseTransform.json`, `addBaseDocCanon.json`, `addBaseDocHMACCanon.json`, `addHashData.json`, `addRawBaseSignatureInfo.json`, `addSignedSDBase.json` |
| 1a. Check pointers | [PointerCheck.js](PointerCheck.js) | unsigned credential, mandatory pointers | `addPointerValues.json` (the value each mandatory pointer selects) |
| 2. Derive proof | [DeriveSteps.js](DeriveSteps.js) | `addSignedSDBase.json`, selective pointers | `derivedRecoveredBaseData.json`, `derivedUnsignedReveal.json`, `derivedAdjSignatures.json`, `derivedDisclosureData.json`, `derivedRevealDocument.json` |
| 3. Verify base proof | [VerifyBaseSteps.js](VerifyBaseSteps.js) | `addSignedSDBase.json` | (console only) |
| 4. Verify derived proof | [VerifyDeriveSteps.js](VerifyDeriveSteps.js) | `derivedRevealDocument.json` | (console only) |

The two end results are `addSignedSDBase.json` (the issuer's signed base credential) and `derivedRevealDocument.json` (the holder's selectively disclosed credential). The other files are intermediate values for implementers to check their work against.

`addBaseDocCanon.json` and `addBaseDocHMACCanon.json` are for illustration only. They show the canonical N-Quads before and after the HMAC blank node relabeling, and are not inputs to any later step.

## Proof values

[proofValue.js](proofValue.js) implements the spec's `serializeBaseProofValue`, `parseBaseProofValue`, `serializeDerivedProofValue` and `parseDerivedProofValue`:

| Proof | Header bytes | CBOR components |
|:--|:--|:--|
| base | `0xd9 0x5d 0x00` | baseSignature, publicKey, hmacKey, signatures, mandatoryPointers |
| derived | `0xd9 0x5d 0x01` | baseSignature, publicKey, signatures, compressedLabelMap, mandatoryIndexes |

SIC uses the HMAC-based blank node label map (labels are base64url HMAC values). The other approaches use the shuffled label map.

All outputs are deterministic: ECDSA signatures here are deterministic, so regenerating gives byte-identical files.
