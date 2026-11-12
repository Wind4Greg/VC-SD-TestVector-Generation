/*
    Walking through the steps for verifying a base BBS proof.
*/
import { repoPath } from '../lib/paths.js'
import { selectExamples } from '../lib/examples.js'
import { mkdir, readFile } from 'fs/promises'
import { klona } from 'klona'
import {
  createHmac, canonicalizeAndGroup
} from '@digitalbazaar/di-sd-primitives'
import { createShuffledIdLabelMapFunction } from './labelMap.js'
import jsonld from 'jsonld'
import { sha256 } from '@noble/hashes/sha256'
import { localLoader } from '../documentLoader.js'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { base58btc } from 'multiformats/bases/base58'
import { decode as decodeCbor } from 'cbor2'
import { base64url } from 'multiformats/bases/base64'
import { API_ID_BBS_SHA, messages_to_scalars as msgsToScalars, prepareGenerators, verify } from './lib/BBS.js'

// Output directory for each supported example; choose examples with --example
const outputDirs = {
  wind: repoPath('BBS/output/bbs/'),
  prc: repoPath('BBS/output/bbs/prc/')
}

for (const name of selectExamples(Object.keys(outputDirs))) {
  console.log(`*** Example: ${name} ***`)
  await verifyExample(outputDirs[name])
}

async function verifyExample (baseDir) {
  await mkdir(baseDir, { recursive: true })

  jsonld.documentLoader = localLoader // Local loader for JSON-LD

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
  const proofValueBytes = base64url.decode(proofValue)
  // console.log(proofValueBytes.length);
  // check header bytes are: 0xd9, 0x5d, and 0x02
  if (proofValueBytes[0] !== 0xd9 || proofValueBytes[1] !== 0x5d || proofValueBytes[2] !== 0x02) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = decodeCbor(proofValueBytes.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  const [bbsSignature, bbsHeaderBase, publicKeyBase, hmacKey, mandatoryPointers] = decodeThing
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
  const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
  const gens = await prepareGenerators(bbsMessages.length + 1, API_ID_BBS_SHA)
  const verified = await verify(pbk, bbsSignature, bbsHeader, msgScalars, gens, API_ID_BBS_SHA)
  console.log(`Base proof verified: ${verified}`)
}
