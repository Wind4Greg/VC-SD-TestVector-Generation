/*
    Signed Individual Claims (SIC) proof values: ecdsa-sd-2023.

    Reference: https://w3c.github.io/vc-di-ecdsa/ (ecdsa-sd-2023 functions)
*/
import { base64url } from 'multiformats/bases/base64'
import {
  serializeProofValue, parseProofValue, checkBytes, checkArrayOf,
  checkIntegerArray, checkCompressedLabelMap
} from '../lib/proofValue.js'

const BASE_HEADER = 0x00
const DERIVED_HEADER = 0x01

/*
  serializeBaseProofValue: initialize a byte array, proofValue, that starts with
  the ECDSA-SD base proof header bytes 0xd9, 0x5d, and 0x00. Initialize
  components to an array with five elements containing the values of:
  baseSignature, publicKey, hmacKey, signatures, and mandatoryPointers.
  CBOR-encode components and append it to proofValue. Return the
  multibase-base64url-no-pad-encoding of proofValue.
*/
export function serializeBaseProofValue ({ baseSignature, publicKey, hmacKey, signatures, mandatoryPointers }) {
  return serializeProofValue(BASE_HEADER,
    [baseSignature, publicKey, hmacKey, signatures, mandatoryPointers])
}

/*
  parseBaseProofValue: check the header bytes 0xd9, 0x5d, 0x00, CBOR-decode the
  remaining bytes and return an object with baseSignature, publicKey, hmacKey,
  signatures, and mandatoryPointers.
*/
export function parseBaseProofValue (proofValue) {
  const [baseSignature, publicKey, hmacKey, signatures, mandatoryPointers] =
    parseProofValue(proofValue, BASE_HEADER, 5)
  return { baseSignature, publicKey, hmacKey, signatures, mandatoryPointers }
}

/*
  compressLabelMap: for each entry (k, v) in labelMap add an entry with a key
  that is a base-10 integer parsed from the characters following the "c14n"
  prefix in k and a value that is a byte array resulting from
  base64url-no-pad-decoding the characters after the "u" prefix in v.
*/
export function compressLabelMap (labelMap) {
  const compressed = new Map()
  labelMap.forEach(function (v, k) {
    const key = parseInt(k.split('c14n')[1])
    const value = base64url.decode(v)
    compressed.set(key, value)
  })
  return compressed
}

/*
  serializeDerivedProofValue: initialize a byte array, proofValue, that starts
  with the ECDSA-SD disclosure proof header bytes 0xd9, 0x5d, and 0x01.
  Initialize components to an array with five elements containing the values
  of: baseSignature, publicKey, signatures, compressedLabelMap (from
  compressLabelMap(labelMap)), and mandatoryIndexes. CBOR-encode components,
  append it to proofValue, and return its multibase-base64url-no-pad-encoding.
*/
export function serializeDerivedProofValue ({ baseSignature, publicKey, signatures, labelMap, mandatoryIndexes }) {
  return serializeProofValue(DERIVED_HEADER,
    [baseSignature, publicKey, signatures, compressLabelMap(labelMap), mandatoryIndexes])
}

/*
  parseDerivedProofValue: check the header bytes 0xd9, 0x5d, 0x01, CBOR-decode
  the rest and ensure the result is an array of five elements: a byte array of
  length 64, a byte array (the multikey-encoded public key, 35 bytes for
  P-256), an array of byte arrays each of length 64, a map of integers to byte
  arrays of length 32, and an array of integers, throwing an error if not.
  The label map is returned in its compressed form.
*/
export function parseDerivedProofValue (proofValue) {
  const [baseSignature, publicKey, signatures, compressedLabelMap, mandatoryIndexes] =
    parseProofValue(proofValue, DERIVED_HEADER, 5)
  checkBytes(baseSignature, 'baseSignature', 64)
  checkBytes(publicKey, 'publicKey')
  checkArrayOf(signatures, 'signatures', sig => checkBytes(sig, 'signature in signatures array', 64))
  checkCompressedLabelMap(compressedLabelMap, v => v instanceof Uint8Array && v.length === 32)
  checkIntegerArray(mandatoryIndexes, 'mandatory indexes')
  return { baseSignature, publicKey, signatures, compressedLabelMap, mandatoryIndexes }
}
