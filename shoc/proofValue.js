/*
    Salted Hash of Claims (SHoC) proof values: mldsa44-sd-2024,
    slhdsa128-sd-2024, falcon512-sd-2024.

    Reference: https://github.com/w3c/vc-di-quantum-resistant
*/
import { compressShuffledLabelMap } from '../lib/labelMaps.js'
import {
  serializeProofValue, parseProofValue, checkBytes, checkArrayOf,
  checkIntegerArray, checkCompressedLabelMap
} from '../lib/proofValue.js'

const BASE_HEADER = 0x10
const DERIVED_HEADER = 0x11

/*
  serializeBaseProofValue: header bytes 0xd9, 0x5d, 0x10 followed by the CBOR
  encoding of [signature, hmacKey, salts, saltedHashes, mandatoryPointers],
  multibase-base64url-no-pad-encoded.
*/
export function serializeBaseProofValue ({ signature, hmacKey, salts, saltedHashes, mandatoryPointers }) {
  return serializeProofValue(BASE_HEADER,
    [signature, hmacKey, salts, saltedHashes, mandatoryPointers])
}

/*
  parseBaseProofValue: check the header bytes 0xd9, 0x5d, 0x10, CBOR-decode the
  rest and return signature, hmacKey, salts, saltedHashes, and
  mandatoryPointers.
*/
export function parseBaseProofValue (proofValue) {
  const [signature, hmacKey, salts, saltedHashes, mandatoryPointers] =
    parseProofValue(proofValue, BASE_HEADER, 5)
  return { signature, hmacKey, salts, saltedHashes, mandatoryPointers }
}

/*
  serializeDerivedProofValue: header bytes 0xd9, 0x5d, 0x11 followed by the
  CBOR encoding of [signature, salts (revealed only), saltedHashes,
  compressedLabelMap, mandatoryIndexes, selectiveIndexes].
*/
export function serializeDerivedProofValue ({ signature, salts, saltedHashes, labelMap, mandatoryIndexes, selectiveIndexes }) {
  return serializeProofValue(DERIVED_HEADER,
    [signature, salts, saltedHashes, compressShuffledLabelMap(labelMap), mandatoryIndexes, selectiveIndexes])
}

/*
  parseDerivedProofValue: check the header bytes 0xd9, 0x5d, 0x11, CBOR-decode
  the rest and check the label map (integers to integers) and the mandatory
  indexes. The label map is returned in its compressed form.
*/
export function parseDerivedProofValue (proofValue) {
  const [signature, salts, saltedHashes, compressedLabelMap, mandatoryIndexes, selectiveIndexes] =
    parseProofValue(proofValue, DERIVED_HEADER, 6)
  checkBytes(signature, 'signature')
  checkArrayOf(salts, 'salts', s => checkBytes(s, 'salt'))
  checkArrayOf(saltedHashes, 'saltedHashes', h => checkBytes(h, 'salted hash'))
  checkCompressedLabelMap(compressedLabelMap, Number.isInteger)
  checkIntegerArray(mandatoryIndexes, 'mandatory indexes')
  checkIntegerArray(selectiveIndexes, 'selective indexes')
  return { signature, salts, saltedHashes, compressedLabelMap, mandatoryIndexes, selectiveIndexes }
}
