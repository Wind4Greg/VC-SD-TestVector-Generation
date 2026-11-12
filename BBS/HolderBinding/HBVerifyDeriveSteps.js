/*
    Walking through the steps and generating test vectors for verifying a derived
    BBS selective disclosure proof with Anonymous Holder Binding feature.

    **CAUTION**: This looks exactly like the regular BBS "verify derived proof" procedure
    **except** that it uses the BBS api_id of API_ID_BLIND_BBS_SHA.
*/

import { repoPath } from '../../lib/paths.js'
import { mkdir, readFile, writeFile } from 'fs/promises'
import { createLabelMapFunction, labelReplacementCanonicalizeJsonLd } from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from '../../lib/documentLoader.js'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { klona } from 'klona'
import { base58btc } from 'multiformats/bases/base58'
import { decode as decodeCbor } from 'cbor2'
import { base64url } from 'multiformats/bases/base64'
import { API_ID_BLIND_BBS_SHA, messages_to_scalars as msgsToScalars,
  prepareGenerators, numUndisclosed, proofVerify } from '../lib/BBS.js'
import { BlindProofVerify } from '../lib/BlindBBS.js'

// Create output directory for the results
const baseDir = repoPath('BBS/output/bbs/HolderBinding/')
const inputDir = repoPath('input/')
await mkdir(baseDir, { recursive: true })

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read base signed document from a file 'revealDocument.json', 'DBderivedCredential.json'
const document = JSON.parse(
  await readFile(
    baseDir + 'derivedRevealDocument.json'
  )
)

const options = { documentLoader: localLoader }

// *Create Verify Data*

const proof = document.proof
const proofValue = proof.proofValue
const proofConfig = klona(document.proof)
delete proofConfig.proofValue
proofConfig['@context'] = document['@context']
delete document.proof // **IMPORTANT** from now on we work with the document without proof!!!!!!!
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8

// console.log(`proofHash: ${bytesToHex(proofHash)}`);
// **Parse Derived Proof Value BBS** [bbsProof, compressLabelMap, adjMandatoryIndexes, adjSelectiveIndexes, lengthBBSMessages]
if (!proofValue.startsWith('u')) {
  throw new Error('proofValue not a valid multibase-64-url encoding')
}
const decodedProofValue = base64url.decode(proofValue)
// check header bytes, specific for Anonymous Holder Binding
if (decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d || decodedProofValue[2] !== 0x05) {
  throw new Error('Invalid proofValue header')
}
const decodeThing = decodeCbor(decodedProofValue.slice(3))
if (decodeThing.length !== 6) {
  throw new Error('Bad length of CBOR decoded proofValue data')
}
const [bbsProof, labelMapCompressed, mandatoryIndexes, adjSelectedIndexes,
  presentationHeader, lengthBBSMessages] = decodeThing
// console.log(baseSignature, typeof baseSignature);
if (!(labelMapCompressed instanceof Map)) {
  throw new Error('Bad label map in proofValue')
}
// Modified for **BBS** labeling, just an integer
labelMapCompressed.forEach(function (value, key) {
  if (!Number.isInteger(key) || !Number.isInteger(value)) {
    throw new Error('Bad key or value in compress label map in proofValue')
  }
})
if (!Array.isArray(mandatoryIndexes)) {
  throw new Error('mandatory indexes is not an array in proofValue')
}
mandatoryIndexes.forEach(value => {
  if (!Number.isInteger(value)) {
    throw new Error('Value in mandatory indexes  is not an integer')
  }
})
const labelMap = new Map()
labelMapCompressed.forEach(function (v, k) {
  const key = 'c14n' + k
  const value = 'b' + v
  labelMap.set(key, value)
})
// console.log(labelMap);
// Could use a test vector here
const derivedProofValue = {
  bbsProof: bytesToHex(bbsProof),
  labelMap: [...labelMap],
  mandatoryIndexes,
  adjSelectedIndexes
}
// console.log(labelMap);
await writeFile(baseDir + 'verifyDerivedProofValue.json', JSON.stringify(derivedProofValue, null, 2))

// Initialize labelMapFactoryFunction to the result of calling the "createLabelMapFunction" algorithm.
const labelMapFactoryFunction = await createLabelMapFunction({ labelMap })
/* Initialize nquads to the result of calling the "labelReplacementCanonicalize" algorithm, passing
  document, labelMapFactoryFunction, and any custom JSON-LD API options. Note: This step transforms
  the document into an array of canonical N-Quads with pseudorandom blank node identifiers based on
  labelMap.
*/
const nquads = await labelReplacementCanonicalizeJsonLd({
  document,
  labelMapFactoryFunction,
  options
})
await writeFile(baseDir + 'verifyNQuads.json', JSON.stringify(nquads, null, 2))
const mandatory = []
const nonMandatory = []
nquads.forEach(function (value, index) {
  if (mandatoryIndexes.includes(index)) {
    mandatory.push(value)
  } else {
    nonMandatory.push(value)
  }
})
const mandatoryHash = sha256(mandatory.join(''))

// Get public key
console.log(proof.verificationMethod.split('did:key:'))
//
const encodedPbk = proof.verificationMethod.split('did:key:')[1].split('#')[0]
console.log(encodedPbk)
let pbk = base58btc.decode(encodedPbk)
pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)

/* Verify BBS Proof */
const bbsHeader = concatBytes(proofHash, mandatoryHash)
const te = new TextEncoder()
const bbsMessages = [...nonMandatory.values()].map(txt => te.encode(txt)) // must be byte arrays
const msgScalars = await msgsToScalars(bbsMessages, API_ID_BLIND_BBS_SHA)
const L = numUndisclosed(bbsProof) + msgScalars.length
const gens = await prepareGenerators(L + 1, API_ID_BLIND_BBS_SHA) // Generate enough for all messages
const ph = presentationHeader
// BlindProofVerify(PK, proof, header, ph, L,
// disclosed_messages, disclosed_committed_messages, disclosed_indexes,
// disclosed_committed_indexes, api_id)
// const verified = await proofVerify(pbk, bbsProof, bbsHeader, ph, msgScalars,
//   adjSelectedIndexes, gens, API_ID_BLIND_BBS_SHA)
const verified = await BlindProofVerify(pbk, bbsProof, bbsHeader, ph, lengthBBSMessages,
  bbsMessages, [], adjSelectedIndexes, [], API_ID_BLIND_BBS_SHA)
console.log(`Derived proof verified: ${verified}`)
