/*
    Steps for creating a derived proof for the Pseudonym feature.
*/

import { repoPath } from '../../lib/paths.js'
import { mkdir, readFile, writeFile } from 'fs/promises'
import {
  createHmac, canonicalizeAndGroup, selectJsonLd,
  canonicalize, stripBlankNodePrefixes
} from '@digitalbazaar/di-sd-primitives'
import { createShuffledIdLabelMapFunction } from '../labelMap.js'
import jsonld from 'jsonld'
import { klona } from 'klona'
import { localLoader } from '../../documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import { decode as decodeCbor, encode as encodeCbor } from 'cbor2'
import { sha256 } from '@noble/hashes/sha256'
import { base64url } from 'multiformats/bases/base64'
import {
  API_ID_PSEUDONYM_BBS_SHA, numberToBytesBE, seeded_random_scalars as seededRandScalars
} from '../lib/BBS.js'
import { BlindVerifyWithNym, ProofGenWithNym } from '../lib/PseudonymBBS.js'
// For serialization of JavaScript Map via JSON
function replacerMap (key, value) { // See https://stackoverflow.com/questions/29085197/how-do-you-json-stringify-an-es6-map
  if (value instanceof Map) {
    return {
      dataType: 'Map',
      value: Array.from(value.entries()) // or with spread: value: [...value]
    }
  } else {
    return value
  }
}

// Create output directory for the test vectors
const baseDir = repoPath('BBS/output/bbs/Pseudonym/')
const inputDir = repoPath('input/')
await mkdir(baseDir, { recursive: true })

// Obtain presentationHeader and process into byte array format
const deriveOptions = JSON.parse(
  await readFile(inputDir + 'BBSDeriveMaterial.json'))
const presentationHeader = hexToBytes(deriveOptions.presentationHeaderHex)

// Get prover(holder) nym information
const proverInfo = JSON.parse(
  await readFile(repoPath('input/proverNym.json')))
console.log(proverInfo.proverNymHex)
const proverNym = BigInt('0x' + proverInfo.proverNymHex)
console.log(proverInfo.proverNymHex)
const commitInfo = JSON.parse(
  await readFile(baseDir + 'commitmentInfo.json'))
const secretProverBlind = BigInt('0x' + commitInfo.secretProverBlind)

// Get verifier identifier and generate pseudonym here
const verifierInfo = JSON.parse(
  await readFile(inputDir + 'verifierInfo.json'))
const te = new TextEncoder()
const nymDomain = te.encode(verifierInfo.nymDomainString) // need as byte array

// Get the selective disclosure pointers
const selectivePointers = JSON.parse(
  await readFile(
    inputDir + 'licenseSelective.json'
  )
)
jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read base signed document from a file
const document = JSON.parse(
  await readFile(
    baseDir + 'addSignedSDBase.json'
  )
)

const options = { documentLoader: localLoader }

// **Create Disclosure Data**

// parseBaseProofValue:
const proof = document.proof
delete document.proof // IMPORTANT: all work uses document without proof
const proofValue = proof.proofValue // base64url encoded
const proofValueBytes = base64url.decode(proofValue)
// console.log(proofValueBytes.length);
// check header bytes are: 0xd9, 0x5d, and 0x00
if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x08) {
  throw new Error('Invalid proofValue header')
}
const decodeThing = decodeCbor(proofValueBytes.slice(3))

if (decodeThing.length !== 6) {
  throw new Error('Bad length of CBOR decoded proofValue data')
}
const [bbsSignature, bbsHeaderBase, publicKey, hmacKey, mandatoryPointers,
  signerNymEntropy] = decodeThing
console.log(signerNymEntropy)
const baseProofData = {
  bbsSignature: bytesToHex(bbsSignature),
  bbsHeader: bytesToHex(bbsHeaderBase),
  publicKey: bytesToHex(publicKey),
  hmacKey: bytesToHex(hmacKey),
  mandatoryPointers,
  signerNymEntropy: signerNymEntropy.toString(16),
  featureOption: 'pseudonym'
}
await writeFile(baseDir + 'derivedRecoveredBaseData.json', JSON.stringify(baseProofData, replacerMap, 2))
// Combine pointers
const combinedPointers = mandatoryPointers.concat(selectivePointers)
// Creating reveal document from combined pointers
const revealDocument = selectJsonLd({ document, pointers: combinedPointers })
await writeFile(baseDir + 'derivedUnsignedReveal.json', JSON.stringify(revealDocument, replacerMap, 2))
// setup HMAC stuff
const hmac = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createShuffledIdLabelMapFunction({ hmac })

// Initialize group definition so we can figure out BBS messages and indexes
const groups = {
  mandatory: mandatoryPointers,
  selective: selectivePointers,
  combined: combinedPointers
}
const stuff = await canonicalizeAndGroup({
  document,
  labelMapFactoryFunction,
  groups,
  options
})
// console.log(JSON.stringify(stuff, replacerMap, 2))
await writeFile(baseDir + 'derivedAllGroupData.json', JSON.stringify(stuff, replacerMap, 2))
const combinedMatch = stuff.groups.combined.matching
const mandatoryMatch = stuff.groups.mandatory.matching
const mandatoryNonMatch = stuff.groups.mandatory.nonMatching
const selectiveMatch = stuff.groups.selective.matching
const combinedIndexes = [...combinedMatch.keys()]
const nonMandatoryIndexes = [...mandatoryNonMatch.keys()]
const selectiveIndexes = [...selectiveMatch.keys()]
const groupIndexes = {
  combinedIndexes,
  mandatoryIndexes: [...mandatoryMatch.keys()],
  nonMandatoryIndexes,
  selectiveIndexes
}
await writeFile(baseDir + 'derivedGroupIndexes.json', JSON.stringify(groupIndexes, replacerMap))
/*
  Compute the "adjusted mandatory indexes" relative to their
  positions in the combined statement list, i.e., find at what position a mandatory
  statement occurs in the list of combined statements.
*/
const adjMandatoryIndexes = []
mandatoryMatch.forEach((value, index) => {
  adjMandatoryIndexes.push(combinedIndexes.indexOf(index))
})
/* Determine which non-mandatory nquad match a selectively disclosed nquad and
  get its index relative to place in the non-mandatory list.
  The non-mandatory nquads are the BBS messages and we need the selective indexes
  relative to this list.
*/
const adjSelectiveIndexes = []
selectiveMatch.forEach((value, index) => {
  const adjIndex = nonMandatoryIndexes.indexOf(index)
  if (adjIndex !== -1) {
    adjSelectiveIndexes.push(adjIndex)
  }
})
// console.log('adjust Signature Indexes:')
// console.log(adjSignatureIndexes)
await writeFile(baseDir + 'derivedAdjIndexes.json',
  JSON.stringify({ adjMandatoryIndexes, adjSelectiveIndexes }))

// **Create Verifier Label Map**
const deskolemizedNQuads = stuff.groups.combined.deskolemizedNQuads
let canonicalIdMap = new Map()
// The goal of the below is to get the canonicalIdMap and not the canonical document
await canonicalize(deskolemizedNQuads.join(''),
  { ...options, inputFormat: 'application/n-quads', canonicalIdMap })
// console.log(JSON.stringify(canonicalIdMap, replacerMap, 2))
canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap)
// console.log(JSON.stringify(canonicalIdMap, replacerMap, 2))
const verifierLabelMap = new Map()
const labelMap = stuff.labelMap
canonicalIdMap.forEach(function (value, key) {
  verifierLabelMap.set(value, labelMap.get(key))
})

// 6. Generate the BBSProofValue (output of BBS proof procedure)
// Recreate BBS header
const proofConfig = klona(proof)
proofConfig['@context'] = document['@context']
delete proofConfig.proofValue // Don't forget to remove this
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon)
const mandatoryCanon = [...mandatoryMatch.values()].join('')
const mandatoryHash = sha256(mandatoryCanon)
const bbsHeader = concatBytes(proofHash, mandatoryHash)

// Recreate BBS messages
const bbsMessages = [...mandatoryNonMatch.values()].map(txt => te.encode(txt)) // must be byte arrays

const ph = presentationHeader
// Note that BBS proofGen usually uses cryptographic random numbers on each run which doesn't
// make for good test vectors instead with use the helper technique use in BBS to generate
// its example proofs
// Pseudo random (deterministic) scalar generation seed and function
const seed = hexToBytes(deriveOptions.pseudoRandSeedHex)
const randScalarFunc = seededRandScalars.bind(null, seed, API_ID_PSEUDONYM_BBS_SHA)

// Need nymSecret
const [verified, nymSecret] = await BlindVerifyWithNym(publicKey, bbsSignature, bbsHeader, bbsMessages, [],
  proverNym, signerNymEntropy, secretProverBlind, API_ID_PSEUDONYM_BBS_SHA)
const nymSecretData = { nymSecretHex: nymSecret.toString(16)}
await writeFile(baseDir + 'nymSecret.json', JSON.stringify(nymSecretData, replacerMap))
const committedMessages = []
const disclosedCommitmentIndexes = []
const [bbsProof, pseudonym] = await ProofGenWithNym(publicKey, bbsSignature, bbsHeader, ph,
  nymSecret, nymDomain, bbsMessages, committedMessages, adjSelectiveIndexes, disclosedCommitmentIndexes,
  secretProverBlind, API_ID_PSEUDONYM_BBS_SHA, randScalarFunc)

// 7. serialize via CBOR: BBSProofValue, compressedLabelMap, mandatoryIndexes, selectiveIndexes, ph, pseudonym

const disclosureData = {
  bbsProof: bytesToHex(bbsProof),
  labelMap: verifierLabelMap,
  mandatoryIndexes: adjMandatoryIndexes,
  adjSelectiveIndexes,
  presentationHeader: ph,
  pseudonym: bytesToHex(pseudonym.toRawBytes(true)),
  featureOption: 'pseudonym',
  lengthBBSMessages: bbsMessages.length
}
await writeFile(baseDir + 'derivedDisclosureData.json', JSON.stringify(disclosureData, replacerMap))

// Initialize newProof to a shallow copy of proof.
const newProof = Object.assign({}, proof)
// Modified for **BBS** unlinkable labeling
const compressLabelMap = new Map()
verifierLabelMap.forEach(function (v, k) {
  const key = parseInt(k.split('c14n')[1])
  const value = parseInt(v.split('b')[1])
  compressLabelMap.set(key, value)
})

// Pseudonym with Hidden Pid header bytes (may change)
let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x09])
const components = [bbsProof, compressLabelMap, adjMandatoryIndexes,
  adjSelectiveIndexes, ph, pseudonym.toRawBytes(true), bbsMessages.length]
const cborThing = encodeCbor(components)
derivedProofValue = concatBytes(derivedProofValue, cborThing)
const derivedProofValueString = base64url.encode(derivedProofValue)
console.log(derivedProofValueString)
console.log(`Length of derivedProofValue is ${derivedProofValueString.length} characters`)
newProof.proofValue = derivedProofValueString
revealDocument.proof = newProof
// console.log(JSON.stringify(revealDocument, null, 2));
writeFile(baseDir + 'derivedRevealDocument.json', JSON.stringify(revealDocument, null, 2))
