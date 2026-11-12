/*
To come up with Derived Proof for BBS we need:

1. BBSSignature (BBS proof input)
2. HMAC key
3. List of non-mandatory messages (BBS proof input)
4. Indexes of selective messages to be revealed (BBS proof input)
5. Need to recreate the header via proofConfig and mandatory disclosure stuff
6. Generate the BBSProofValue (output of BBS proof procedure)
7. serialize via CBOR: BBSProofValue, compressedLabelMap, mandatoryIndexes,
    adjusted selective indexes (needed for BBS proof verify)

*/

import { repoPath } from '../lib/paths.js';
import { mkdir, readFile, writeFile } from 'fs/promises'
import {createDisclosureData} from '../CommonAlgs.js';
import jsonld from 'jsonld'
import { klona } from 'klona'
import { localLoader } from '../documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import { decode as decodeCbor, encode as encodeCbor } from 'cbor2'
import { sha256 } from '@noble/hashes/sha256'
import { base64url } from 'multiformats/bases/base64'
import {
  API_ID_BBS_SHA, messages_to_scalars as msgsToScalars, prepareGenerators,
  proofGen, seeded_random_scalars as seededRandScalars
} from './lib/BBS.js'
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

// Obtain presentationHeader and process into byte array format
const deriveOptions = JSON.parse(
  await readFile(repoPath('input/BBSDeriveMaterial.json')))
const presentationHeader = hexToBytes(deriveOptions.presentationHeaderHex)

// const dirsAndFiles = {
//   outputDir: repoPath('BBS/output/bbs/'),
//   inputFile: repoPath('input/windSelective.json')
// }

const dirsAndFiles = {
  outputDir: repoPath('BBS/output/bbs/prc/'),
  inputFile: repoPath('input/prCredSelective.json')
}

// Create output directory for the test vectors
const baseDir = dirsAndFiles.outputDir
await mkdir(baseDir, { recursive: true })

// Get the selective disclosure pointers, either windSelective.json or treeSelective.json
const selectivePointers = JSON.parse(
  await readFile(
    dirsAndFiles.inputFile
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

// **parse Base Proof Value**
const proof = document.proof
delete document.proof // IMPORTANT: all work uses document without proof
const proofValue = proof.proofValue // base64url encoded
const proofValueBytes = base64url.decode(proofValue)
// console.log(proofValueBytes.length);
// check header bytes are: 0xd9, 0x5d, and 0x00
if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x02) {
  throw new Error('Invalid proofValue header')
}
const decodeThing = decodeCbor(proofValueBytes.slice(3))

if (decodeThing.length !== 5) {
  throw new Error('Bad length of CBOR decoded proofValue data')
}
const [bbsSignature, bbsHeaderBase, publicKey, hmacKey, mandatoryPointers] = decodeThing
const baseProofData = {
  bbsSignature: bytesToHex(bbsSignature),
  hmacKey: bytesToHex(hmacKey),
  mandatoryPointers
}
await writeFile(baseDir + 'derivedRecoveredBaseData.json', JSON.stringify(baseProofData, replacerMap, 2))

// **Create Disclosure Data**
// Note false at the end ==> do not use legacy ECDSA-SD label map.
const {revealDocument, mandatoryIndexes, selectiveIndexes, verifierLabelMap, 
  mandatory, nonMandatory} = await createDisclosureData(document, 
    mandatoryPointers, selectivePointers, hmacKey, false);

await writeFile(baseDir + 'derivedUnsignedReveal.json', JSON.stringify(revealDocument, replacerMap, 2))

await writeFile(baseDir + 'derivedAdjIndexes.json',
  JSON.stringify({ adjMandatoryIndexes: mandatoryIndexes, adjSelectiveIndexes: selectiveIndexes }))

// 6. Generate the BBSProofValue (output of BBS proof procedure)
// Recreate BBS header
const proofConfig = klona(proof)
proofConfig['@context'] = document['@context']
delete proofConfig.proofValue // Don't forget to remove this
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon)
const mandatoryCanon = [...mandatory.values()].join('')
const mandatoryHash = sha256(mandatoryCanon)
const bbsHeader = concatBytes(proofHash, mandatoryHash)

// Recreate BBS messages
const te = new TextEncoder()
const bbsMessages = [...nonMandatory.values()].map(txt => te.encode(txt)) // must be byte arrays
const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
// calc generators -- note in production these values would be cached since they are reusable
const gens = await prepareGenerators(bbsMessages.length + 1, API_ID_BBS_SHA)
// Get issuer public key
// const encodedPbk = proof.verificationMethod.split('did:key:')[1].split('#')[0]
// let pbk = base58btc.decode(encodedPbk)
// pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
// // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)
const ph = presentationHeader
// Note that BBS proofGen usually uses cryptographic random numbers on each run which doesn't
// make for good test vectors instead with use the helper technique use in BBS to generate
// its example proofs
// Pseudo random (deterministic) scalar generation seed and function
const seed = hexToBytes(deriveOptions.pseudoRandSeedHex)
const randScalarFunc = seededRandScalars.bind(null, seed, API_ID_BBS_SHA)
const bbsProof = await proofGen(publicKey, bbsSignature, bbsHeader, ph, msgScalars,
  selectiveIndexes, gens, API_ID_BBS_SHA, randScalarFunc)

// 7. serialize via CBOR: BBSProofValue, compressedLabelMap, mandatoryIndexes, selectiveIndexes, ph

const disclosureData = {
  bbsProof: bytesToHex(bbsProof),
  labelMap: verifierLabelMap,
  mandatoryIndexes: mandatoryIndexes,
  adjSelectiveIndexes: selectiveIndexes,
  presentationHeader: ph
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

let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x03])
const components = [bbsProof, compressLabelMap, mandatoryIndexes, selectiveIndexes, ph]
const cborThing = encodeCbor(components)
derivedProofValue = concatBytes(derivedProofValue, cborThing)
const derivedProofValueString = base64url.encode(derivedProofValue)
console.log(derivedProofValueString)
console.log(`Length of derivedProofValue is ${derivedProofValueString.length} characters`)
newProof.proofValue = derivedProofValueString
revealDocument.proof = newProof
// console.log(JSON.stringify(revealDocument, null, 2));
writeFile(baseDir + 'derivedRevealDocument.json', JSON.stringify(revealDocument, null, 2))
