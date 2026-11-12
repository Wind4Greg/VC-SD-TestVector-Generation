/*
    Proof value encoding shared by all selective disclosure approaches.

    Every SD proof value is a multibase-base64url-no-pad string ("u" prefix)
    of: the three header bytes 0xd9, 0x5d, <type> followed by the CBOR encoding
    of an array of components. Only the type byte and the components differ
    between approaches (SIC, SHoC, BBS) and between base and derived proofs.
*/
import { decode as decodeCbor, encode as encodeCbor } from 'cbor2'
import { concatBytes } from '@noble/hashes/utils'
import { base64url } from 'multiformats/bases/base64'

/**
 * Serialize proof value components.
 * @param {number} headerType - third header byte identifying the proof type
 * @param {Array} components - values to CBOR-encode, in order
 * @returns {string} multibase-base64url-no-pad-encoded proof value
 */
export function serializeProofValue (headerType, components) {
  const header = new Uint8Array([0xd9, 0x5d, headerType])
  return base64url.encode(concatBytes(header, encodeCbor(components)))
}

/**
 * Parse a proof value, checking its encoding, header and component count.
 * @param {string} proofValue - multibase-base64url-no-pad-encoded proof value
 * @param {number} headerType - expected third header byte
 * @param {number} numComponents - expected number of CBOR array elements
 * @returns {Array} the decoded components
 */
export function parseProofValue (proofValue, headerType, numComponents) {
  if (typeof proofValue !== 'string' || !proofValue.startsWith('u')) {
    throw new Error('proofValue not a valid multibase-64-url encoding')
  }
  const bytes = base64url.decode(proofValue)
  if (bytes[0] !== 0xd9 || bytes[1] !== 0x5d || bytes[2] !== headerType) {
    throw new Error('Invalid proofValue header')
  }
  const components = decodeCbor(bytes.slice(3))
  if (!Array.isArray(components) || components.length !== numComponents) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  return components
}

// Validation helpers for parsed components

export function checkBytes (value, name, length) {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) {
    throw new Error(`Bad ${name} in proofValue`)
  }
}

export function checkArrayOf (value, name, check) {
  if (!Array.isArray(value)) {
    throw new Error(`${name} in proofValue is not an array`)
  }
  value.forEach(check)
}

export function checkIntegerArray (value, name) {
  checkArrayOf(value, name, v => {
    if (!Number.isInteger(v)) {
      throw new Error(`Value in ${name} is not an integer`)
    }
  })
}

export function checkCompressedLabelMap (labelMap, checkValue) {
  if (!(labelMap instanceof Map)) {
    throw new Error('Bad label map in proofValue')
  }
  labelMap.forEach((value, key) => {
    if (!Number.isInteger(key) || !checkValue(value)) {
      throw new Error('Bad key or value in compress label map in proofValue')
    }
  })
}
