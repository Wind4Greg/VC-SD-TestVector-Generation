# SHoC specification issues

Issues found in the [VC-Data-Integrity](https://w3c.github.io/vc-data-integrity/) SHoC algorithms while implementing them and producing test vectors. Each entry gives the spec section, what we found, how we found it, and a suggested fix. Reviewed against `w3c/vc-data-integrity` main at `2864e1c` (2026-11-12) unless an entry says otherwise.

Status values: **open** (not yet raised), **raised** (link to the GitHub issue or PR), **resolved**, **no change** (reviewed, no spec change needed).

## 1. ParseDerived-SHoC gives the wrong type for the compressed label map

- **Section:** [ParseDerived-SHoC](https://w3c.github.io/vc-data-integrity/#ParseDerived-SHoC), the list of seven expected components.
- **Found:** the spec says `compressedLabelMap` is "a map of integers to byte arrays, each of length 32". That describes the SIC (HMAC-based) label map. For any cryptosuite other than `ecdsa-sd-2023`, the spec uses `createShuffledIdLabelMapFunction`, whose compressed label map maps integers to integers.
- **How:** reading the spec while planning `shoc/proofValue.js`. The current SHoC code here already parses an integer-to-integer map.
- **Suggested fix:** "a map of integers to integers (|compressedLabelMap|)".
- **Status:** raised: branch `shoc-edits` on w3c/vc-data-integrity, commit `a5e06ac`. The change matches the suggested fix.

## 2. The Merkle root alone does not bind `treeSize` (informative)

- **Section:** [VerifySubtreeProof](https://w3c.github.io/vc-data-integrity/#VerifySubtreeProof), the closing note; [SerializeBase-SHoC](https://w3c.github.io/vc-data-integrity/#SerializeBase-SHoC).
- **Found:** a subtree proof reconstructs the same root for many claimed tree sizes. With 20 leaves and leaves 0, 1, 7, 12 disclosed, every claimed `treeSize` from 17 to 32 gives the original root. All of those trees split at the root into leaves `[0, 16)` and an undisclosed right subtree, which is a single proof value whatever its size.
- **How:** a negative test in [tools/merkleCheck.js](../tools/merkleCheck.js) expected a wrong `treeSize` to fail. It didn't, and the check now demonstrates this behavior instead.
- **Assessment:** not a vulnerability. The spec signs `uint64be(treeSize)` with the root, and the note in VerifySubtreeProof says `treeSize` must be covered by the base signature.
- **Suggested fix:** add a concrete example to that note (like the one above), so implementers see why including `treeSize` in `toSign` is essential, not just tidy.
- **Status:** no change. The existing note is enough; kept here as background.

## 3. Redundant subtree proof length check in VerifyDerived-SHoC (editorial)

- **Section:** [VerifyDerived-SHoC](https://w3c.github.io/vc-data-integrity/#VerifyDerived-SHoC), the check that the subtree proof length matches the expected number of emitted hashes.
- **Found:** VerifySubtreeProof already rejects a proof that is too short (the proof cursor runs past the end) or too long (the proof is not fully used). The earlier length check catches nothing new, and it costs an extra traversal.
- **How:** implementing both in [merkle.js](merkle.js) (`expectedProofLength` and `verifySubtreeProof`). The negative tests for extra and missing proof values fail in `verifySubtreeProof` alone.
- **Suggested fix:** either drop the check, or keep it and say it is an optional early exit.
- **Status:** raised: branch `shoc-edits` on w3c/vc-data-integrity, commit `c360124`, which drops the check. A wrong-length proof is still rejected, by VerifySubtreeProof's cursor checks. The outcome changes from a raised `PROOF_VERIFICATION_ERROR` to `verified` = `false`, the same as any other reconstruction failure.

## 4. compressLabelMap and decompressLabelMap callers don't pass the cryptosuite

- **Section:** [compressLabelMap](https://w3c.github.io/vc-data-integrity/#compresslabelmap) and [decompressLabelMap](https://w3c.github.io/vc-data-integrity/#decompresslabelmap), and their callers: SerializeDerived-SHoC and ParseDerived-SHoC, and also the SIC serialize step.
- **Found:** both algorithms take `cryptosuite` as an input, and need it to choose between the integer→bytes form (`ecdsa-sd-2023`) and the integer→integer form. Only the SIC parse step passes it. The SIC serialize step and both SHoC calls ("passing |labelMap| as the parameter", "passing the existing sixth element of |components| as |compressedLabelMap|") leave it out. That leaves the SHoC branch unspecified.
- **How:** checking the issue #1 PR against the decompressLabelMap text (reviewed against `shoc-edits` at `c360124`).
- **Suggested fix:** add "and |cryptosuite|" to each call that leaves it out. Also make `cryptosuite` an input of SerializeDerived-SIC, ParseDerived-SIC, SerializeDerived-SHoC and ParseDerived-SHoC (none of them lists it), and pass `|proof|.cryptosuite` from the dispatch steps in Add Derived Proof and Verify Derived Proof.
- **Status:** raised: branch `shoc-edits`, commit `f8ef6cc`, which adds `cryptosuite` to all four calls. Still to do: add `cryptosuite` as an input of the four algorithms and pass it from the dispatch steps.

## Related, outside the spec

- [SimpleMerkle](https://github.com/Wind4Greg/SimpleMerkle) throws for `treeSize` 0 and 1, because `rootName` is never set when the tree has no internal node. The spec defines both cases, and [merkle.js](merkle.js) handles them.
