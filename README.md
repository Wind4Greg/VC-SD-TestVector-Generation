# Test Vectors for VC Selective Disclosure

This repository contains JavaScript (Node.js) code that generates the selective disclosure (SD) test vectors for these specifications:

| Approach | Folder | Cryptosuites | Specification |
|:--|:--|:--|:--|
| Signed Individual Claims (SIC) | [sic/](sic/) | `ecdsa-sd-2023` | [VC-DI-ECDSA](https://w3c.github.io/vc-di-ecdsa/) |
| Salted Hash of Claims (SHoC) | [shoc/](shoc/) | `mldsa44-sd-2024`, `slhdsa128-sd-2024`, `falcon512-sd-2024` | [VC-DI-Quantum-Resistant](https://github.com/w3c/vc-di-quantum-resistant) |
| BBS | [bbs/](bbs/) | `bbs-2023`, including anonymous holder binding and pseudonyms | [VC-DI-BBS](https://github.com/w3c/vc-di-bbs) |

The algorithms the three approaches share have been factored out into the [VC-Data-Integrity](https://github.com/w3c/vc-data-integrity) specification. The approaches differ in how claims are signed:

* **SIC** signs each non-mandatory claim individually. It suits signature algorithms with short signatures, such as ECDSA.
* **SHoC** signs one list of salted claim hashes. It suits algorithms with long signatures, such as the post-quantum ones.
* **BBS** provides selective disclosure at the cryptographic layer, and its derived proofs are unlinkable.

Each specification repository keeps its test vectors in its own test vector directory. The files are copied there from the output folders here.

## Quick start

```
npm install
npm test            # verify all committed test vectors (changes nothing)
npm run gen:all     # regenerate all test vectors
```

To regenerate one approach, use `npm run gen:sic`, `gen:shoc` or `gen:bbs`. To regenerate only some examples, add `--example`:

```
npm run gen:sic -- --example prc
npm run gen:all -- -e wind,prc
```

Groups that don't support the requested examples are skipped. The generator stops a group and exits non-zero if a step fails or any verification reports `verified: false`.

Each step script can also be run on its own from any directory, for example `node sic/AddBaseSteps.js -e employ`. The steps in each approach depend on each other's outputs, so run them in the order given in that approach's README.

### Which outputs change when regenerated

The SIC and BBS baseline outputs are deterministic: regenerating them gives byte-identical files. Some outputs change on every run, because the algorithms call for fresh randomness:

* **SHoC:** the salts.
* **BBS holder binding and pseudonym features:** the commitments and the proofs.

For those, `npm test` is the check that matters.

## Repository layout

```
lib/        code shared by all approaches
  sdCommon.js       VC-DI common SD algorithms (see below)
  labelMaps.js      blank node label map functions
  proofValue.js     proof value encoding: header bytes + CBOR + multibase
  examples.js       example registry and the --example option
  paths.js          repo-root-relative paths
  documentLoader.js, contexts/   local JSON-LD context loading
sic/        SIC step scripts, proof values, output/
shoc/       SHoC step scripts, proof values, output/
bbs/        BBS step scripts per feature, BBS crypto (bbs/lib/), output/
input/      example credentials, pointers, and key material
tools/      generate.js (the npm scripts) and small investigation scripts
```

Output folders are organized as `<approach>/output/<suite or feature>/<example>/`. File names start with the step that produced them:

* `add…`: creating the base proof.
* `derived…`: creating the derived (disclosure) proof.
* `verify…`: verifying.

### Shared algorithms

[lib/sdCommon.js](lib/sdCommon.js) implements the VC-Data-Integrity selective disclosure functions that every approach uses:

| Function | Purpose |
|:--|:--|
| `proofConfigCanon` | Base proof configuration: canonicalize the proof options. |
| `transformSD` | Base proof transformation: canonicalize, apply the label map, and split into mandatory and non-mandatory N-Quads. |
| `hashingSD` | Base proof hashing: `proofHash` and `mandatoryHash`. |
| `saltedHashingSD` | Salts and salted hashes of the non-mandatory N-Quads (SHoC only). |
| `createDisclosureData` | Reveal document, label map, mandatory and selective indexes for a derived proof. |
| `createVerifyData` | `proofHash`, `mandatoryHash` and non-mandatory N-Quads for verifying a derived proof. |

The approach-specific parts are serialization, parsing and the cryptography. They live in each approach's `proofValue.js` and step scripts.

## Examples

| Name | Unsigned credential | Mandatory pointers | Selective pointers | Used by |
|:--|:--|:--|:--|:--|
| `wind` | [windDoc.json](input/windDoc.json) | [windMandatory.json](input/windMandatory.json) | [windSelective.json](input/windSelective.json) | SIC, BBS baseline |
| `employ` | [employmentAuth.json](input/employmentAuth.json) | [employMandatory.json](input/employMandatory.json) | [employSelective.json](input/employSelective.json) | SIC, SHoC |
| `prc` | [prCredUnsigned.json](input/prCredUnsigned.json) | [prCredMandatory.json](input/prCredMandatory.json) | [prCredSelective.json](input/prCredSelective.json) | SIC, BBS baseline |
| `license` | [license.json](input/license.json) | [licenseMandatory.json](input/licenseMandatory.json) | [licenseSelective.json](input/licenseSelective.json) | BBS features |
| `tree` | [treeDoc.json](input/treeDoc.json) | [treeMandatory.json](input/treeMandatory.json) | [treeSelective.json](input/treeSelective.json) | (registered, not currently generated) |

The mandatory pointers are the JSON Pointers the issuer requires every holder to reveal. The selective pointers are the additional claims the holder chooses to reveal.

To add an example:

1. Add its three input files to `input/`.
2. Register it in [lib/examples.js](lib/examples.js).
3. Add an output folder for it to the `outputDirs` map in each step script that should generate it, and to the group's `examples` list in [tools/generate.js](tools/generate.js).
4. If the credential uses a JSON-LD context that isn't already in `lib/contexts/`, add the context there and register it in [lib/documentLoader.js](lib/documentLoader.js).

## To do

The [VC-Data-Integrity](https://github.com/w3c/vc-data-integrity) SHoC approach has been updated with two optimizations. These still need to be implemented here, and new test vectors produced.

## Libraries used

* [@noble/hashes](https://github.com/paulmillr/noble-hashes): hashes and HMAC.
* [@noble/curves](https://github.com/paulmillr/noble-curves): ECDSA and BLS12-381 curve operations.
* [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum): ML-DSA, SLH-DSA and Falcon signatures.
* [jsonld](https://github.com/digitalbazaar/jsonld.js): JSON-LD processing and RDF canonicalization.
* [@digitalbazaar/di-sd-primitives](https://github.com/digitalbazaar/di-sd-primitives): selective disclosure primitives.
* [multiformats](https://github.com/multiformats/js-multiformats): multibase encoding.
* [cbor2](https://github.com/hildjj/cbor2): CBOR encoding of proof values.
* [klona](https://www.npmjs.com/package/klona): deep cloning.
* [json-pointer](https://www.npmjs.com/package/json-pointer): checking the example pointers (`sic/PointerCheck.js`).
