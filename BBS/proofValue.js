/*
    BBS proof values: bbs-2023 baseline (no holder binding or pseudonyms).

    Reference: https://w3c.github.io/vc-di-bbs/
*/
import { compressShuffledLabelMap } from '../lib/labelMaps.js'
import {
  serializeProofValue, parseProofValue, checkBytes, checkIntegerArray,
  checkCompressedLabelMap
} from '../lib/proofValue.js'

const BASE_HEADER = 0x02
const DERIVED_HEADER = 0x03

/*
  serializeBaseProofValue: header bytes 0xd9, 0x5d, 0x02 followed by the CBOR
  encoding of [bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers].
*/
export function serializeBaseProofValue ({ bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers }) {
  return serializeProofValue(BASE_HEADER,
    [bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers])
}

/*
  parseBaseProofValue: check the header bytes 0xd9, 0x5d, 0x02, CBOR-decode the
  rest and return bbsSignature, bbsHeader, publicKey, hmacKey, and
  mandatoryPointers.
*/
export function parseBaseProofValue (proofValue) {
  const [bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers] =
    parseProofValue(proofValue, BASE_HEADER, 5)
  return { bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers }
}

/*
  serializeDerivedProofValue: header bytes 0xd9, 0x5d, 0x03 followed by the
  CBOR encoding of [bbsProof, compressedLabelMap, mandatoryIndexes,
  selectiveIndexes, presentationHeader].
*/
export function serializeDerivedProofValue ({ bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader }) {
  return serializeProofValue(DERIVED_HEADER,
    [bbsProof, compressShuffledLabelMap(labelMap), mandatoryIndexes, selectiveIndexes, presentationHeader])
}

/*
  parseDerivedProofValue: check the header bytes 0xd9, 0x5d, 0x03, CBOR-decode
  the rest and check the label map (integers to integers) and the indexes.
  The label map is returned in its compressed form.
*/
export function parseDerivedProofValue (proofValue) {
  const [bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader] =
    parseProofValue(proofValue, DERIVED_HEADER, 5)
  checkBytes(bbsProof, 'bbsProof')
  checkCompressedLabelMap(compressedLabelMap, Number.isInteger)
  checkIntegerArray(mandatoryIndexes, 'mandatory indexes')
  checkIntegerArray(selectiveIndexes, 'selective indexes')
  checkBytes(presentationHeader, 'presentationHeader')
  return { bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader }
}
