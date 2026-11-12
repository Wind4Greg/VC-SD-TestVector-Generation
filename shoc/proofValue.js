/*
    Salted Hash of Claims (SHoC) proof values with Merkle tree aggregation
    and salt seeds: mldsa44-sd-2024, slhdsa128-sd-2024, falcon512-sd-2024.

    Spec sections (VC-Data-Integrity):
      https://w3c.github.io/vc-data-integrity/#SerializeBase-SHoC
      https://w3c.github.io/vc-data-integrity/#ParseBase-SHoC
      https://w3c.github.io/vc-data-integrity/#SerializeDerived-SHoC
      https://w3c.github.io/vc-data-integrity/#ParseDerived-SHoC

    The header bytes 0x12 / 0x13 replace the earlier 0x10 / 0x11, whose
    proofs carried every salt and salted hash. The spec calls both values
    tentative.
*/
import { compressShuffledLabelMap } from '../lib/labelMaps.js'
import {
  serializeProofValue, parseProofValue, checkBytes, checkArrayOf,
  checkIntegerArray, checkStringArray, checkCompressedLabelMap
} from '../lib/proofValue.js'
import { checkLeafIndexes } from './merkle.js'
import { SALT_LENGTH } from './salts.js'

const BASE_HEADER = 0x12
const DERIVED_HEADER = 0x13
const HASH_LENGTH = 32 // SHA-256

// Policy upper bound on treeSize, enforced before any tree algorithm runs
// (ParseDerived-SHoC: deployment policy, SHOULD be at most 2^24).
export const MAX_TREE_SIZE = 2 ** 24

function checkTreeSize (treeSize, max = Infinity) {
  if (!Number.isInteger(treeSize) || treeSize < 0) {
    throw new Error('treeSize in proofValue is not a non-negative integer')
  }
  if (treeSize > max) {
    throw new Error(`treeSize ${treeSize} exceeds the policy bound ${max}`)
  }
}

/*
  serializeBaseProofValue: header bytes 0xd9, 0x5d, 0x12 followed by the CBOR
  encoding of [signature, hmacKey, saltSeed, treeSize, merkleRoot,
  mandatoryPointers], multibase-base64url-no-pad-encoded. The salts are not
  included; the holder derives them from saltSeed.
*/
export function serializeBaseProofValue ({ signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers }) {
  return serializeProofValue(BASE_HEADER,
    [signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers])
}

/*
  parseBaseProofValue: check the header bytes 0xd9, 0x5d, 0x12, CBOR-decode
  the rest into six components and validate them: saltSeed 16-32 bytes,
  treeSize a non-negative integer, merkleRoot and hmacKey the hash length,
  mandatoryPointers an array of strings.
*/
export function parseBaseProofValue (proofValue) {
  const [signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers] =
    parseProofValue(proofValue, BASE_HEADER, 6)
  checkBytes(signature, 'signature')
  checkBytes(hmacKey, 'hmacKey', HASH_LENGTH)
  if (!(saltSeed instanceof Uint8Array) || saltSeed.length < 16 || saltSeed.length > 32) {
    throw new Error('Bad saltSeed in proofValue')
  }
  checkTreeSize(treeSize)
  checkBytes(merkleRoot, 'merkleRoot', HASH_LENGTH)
  checkStringArray(mandatoryPointers, 'mandatoryPointers')
  return { signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers }
}

/*
  serializeDerivedProofValue: header bytes 0xd9, 0x5d, 0x13 followed by the
  CBOR encoding of [signature, treeSize, leafIndexes, filteredSalts,
  subtreeProof, compressedLabelMap, mandatoryIndexes]. filteredSalts are the
  salts of the disclosed leaves only, in leafIndexes order.
*/
export function serializeDerivedProofValue ({ signature, treeSize, leafIndexes, filteredSalts, subtreeProof, labelMap, mandatoryIndexes }) {
  return serializeProofValue(DERIVED_HEADER,
    [signature, treeSize, leafIndexes, filteredSalts, subtreeProof,
      compressShuffledLabelMap(labelMap), mandatoryIndexes])
}

/*
  parseDerivedProofValue: check the header bytes 0xd9, 0x5d, 0x13, CBOR-decode
  the rest into seven components and validate them. treeSize is checked
  against the policy bound first. leafIndexes must be strictly ascending
  within [0, treeSize); there must be one salt per leaf index; salts and
  subtree proof values must have the salt and hash lengths. The label map
  (integers to integers, see SPEC_ISSUES.md #1) is returned compressed.
*/
export function parseDerivedProofValue (proofValue, { maxTreeSize = MAX_TREE_SIZE } = {}) {
  const [signature, treeSize, leafIndexes, salts, subtreeProof, compressedLabelMap, mandatoryIndexes] =
    parseProofValue(proofValue, DERIVED_HEADER, 7)
  checkBytes(signature, 'signature')
  checkTreeSize(treeSize, maxTreeSize)
  checkIntegerArray(leafIndexes, 'leafIndexes')
  checkLeafIndexes(treeSize, leafIndexes)
  checkArrayOf(salts, 'salts', s => checkBytes(s, 'salt', SALT_LENGTH))
  if (salts.length !== leafIndexes.length) {
    throw new Error('Number of salts does not match number of leafIndexes')
  }
  checkArrayOf(subtreeProof, 'subtreeProof', h => checkBytes(h, 'subtree proof value', HASH_LENGTH))
  checkCompressedLabelMap(compressedLabelMap, Number.isInteger)
  checkIntegerArray(mandatoryIndexes, 'mandatory indexes')
  return { signature, treeSize, leafIndexes, salts, subtreeProof, compressedLabelMap, mandatoryIndexes }
}
