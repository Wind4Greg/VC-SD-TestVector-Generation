/*
    Walking through the steps for verifying a base BBS proof with Anonymous
    Holder Binding.
*/
import { repoPath } from '../../lib/paths.js'
import { parseBaseProofValue } from '../proofValue.js'
import { mkdir, readFile } from 'fs/promises'
import { klona } from 'klona'
import {
  createHmac, canonicalizeAndGroup
} from '@digitalbazaar/di-sd-primitives'
import { createShuffledIdLabelMapFunction } from '../../lib/labelMaps.js'
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { localLoader } from '../../lib/documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64'
import { API_ID_BLIND_BBS_SHA } from '../lib/BBS.js'
import { BlindVerify } from '../lib/BlindBBS.js'
import { bytesToNumberBE } from '@noble/curves/abstract/utils'

// Create output directory for the test vectors
const baseDir = repoPath('bbs/output/HolderBinding/license/')
const inputDir = repoPath('input/')
await mkdir(baseDir, { recursive: true })

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Get holder secret information
const holderSecret = JSON.parse(
  await readFile(inputDir + 'holderSecret.json'))
console.log(holderSecret.holderSecretHex)
const holderSecretMaterial = hexToBytes(holderSecret.holderSecretHex)
const commitInfo = JSON.parse(
  await readFile(baseDir + 'commitmentInfo.json'))
const secretProverBlind = BigInt('0x' + commitInfo.secretProverBlind)

// Read base signed document from a file
const document = JSON.parse(
  await readFile(
    baseDir + 'addSignedSDBase.json'
  )
)

const options = { documentLoader: localLoader }

// parseBaseProofValue:
const proof = document.proof
delete document.proof // IMPORTANT: all work uses document without proof
const proofValue = proof.proofValue // base64url encoded
const { bbsSignature, bbsHeader: bbsHeaderBase, publicKey: publicKeyBase, hmacKey, mandatoryPointers } =
  parseBaseProofValue(proofValue, 'anonymous_holder_binding')
// setup HMAC stuff
const hmac = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createShuffledIdLabelMapFunction({ hmac })

const groups = {
  mandatory: mandatoryPointers
}
const stuff = await canonicalizeAndGroup({
  document,
  labelMapFactoryFunction,
  groups,
  options
})
const mandatoryMatch = stuff.groups.mandatory.matching
const mandatoryNonMatch = stuff.groups.mandatory.nonMatching

// canonize proof configuration and hash it
const proofConfig = klona(proof)
proofConfig['@context'] = document['@context']
delete proofConfig.proofValue // Don't forget to remove this
const proofCanon = await jsonld.canonize(proofConfig)
const proofHash = sha256(proofCanon)
console.log(`proofHash: ${bytesToHex(proofHash)}`)
const mandatoryCanon = [...mandatoryMatch.values()].join('')
const mandatoryHash = sha256(mandatoryCanon)
console.log(`mandatory hash: ${bytesToHex(mandatoryHash)}`)

// Get issuer public key
// console.log(proof.verificationMethod.split('did:key:'))
const encodedPbk = proof.verificationMethod.split('did:key:')[1].split('#')[0]
let pbk = base58btc.decode(encodedPbk)
pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)
// **Verify BBS signature**
const bbsHeader = concatBytes(proofHash, mandatoryHash)
if (bytesToHex(bbsHeader) !== bytesToHex(bbsHeaderBase)) {
  console.log('computed bbsHeader and bbsHeader from base DO NOT match!')
}
const te = new TextEncoder()
const bbsMessages = [...mandatoryNonMatch.values()].map(txt => te.encode(txt)) // must be byte arrays
// BlindVerify(PK, signature, header, messages, committed_messages, secret_prover_blind, api_id)
const verified = await BlindVerify(pbk, bbsSignature, bbsHeader, bbsMessages, [holderSecretMaterial],
  secretProverBlind, API_ID_BLIND_BBS_SHA)

console.log(`Base proof verified: ${verified}`)
