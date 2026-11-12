/*
    Walking through the steps and generating test vectors for verifying a derived
    BBS selective disclosure proof using selective disclosure primitive functions.
*/

import { repoPath } from '../lib/paths.js';
import { selectExamples } from '../lib/examples.js';
import {createVerifyData} from '../CommonAlgs.js';
import { mkdir, readFile, writeFile } from 'fs/promises'
import { createLabelMapFunction, labelReplacementCanonicalizeJsonLd } from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from '../documentLoader.js'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { klona } from 'klona'
import { base58btc } from 'multiformats/bases/base58'
import { decode as decodeCbor } from 'cbor2'
import { base64url } from 'multiformats/bases/base64'
import { API_ID_BBS_SHA, messages_to_scalars as msgsToScalars,
  prepareGenerators, numUndisclosed, proofVerify } from './lib/BBS.js'

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

  // Read base signed document from a file 'revealDocument.json', 'DBderivedCredential.json'
  const document = JSON.parse(
    await readFile(
      baseDir + 'derivedRevealDocument.json'
    )
  )

  const options = { documentLoader: localLoader }

  // *Parse Derived Proof*

  const proof = document.proof
  const proofValue = proof.proofValue

  // **Parse Derived Proof Value BBS** [bbsProof, compressLabelMap, adjMandatoryIndexes, adjSelectiveIndexes]
  if (!proofValue.startsWith('u')) {
    throw new Error('proofValue not a valid multibase-64-url encoding')
  }
  const decodedProofValue = base64url.decode(proofValue)
  // check header bytes
  if (decodedProofValue[0] !== 0xd9 || decodedProofValue[1] !== 0x5d || decodedProofValue[2] !== 0x03) {
    throw new Error('Invalid proofValue header')
  }
  const decodeThing = decodeCbor(decodedProofValue.slice(3))
  if (decodeThing.length !== 5) {
    throw new Error('Bad length of CBOR decoded proofValue data')
  }
  const [bbsProof, labelMapCompressed, mandatoryIndexes, adjSelectedIndexes, presentationHeader] = decodeThing

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

  // get additional verify data
  const {proofHash, mandatoryHash, nonMandatory} = await createVerifyData(document, labelMapCompressed, mandatoryIndexes);

  // Could use a test vector here
  // const derivedProofValue = {
  //   bbsProof: bytesToHex(bbsProof),
  //   labelMap: [...labelMap],
  //   mandatoryIndexes,
  //   adjSelectedIndexes
  // }
  // console.log(labelMap);
  // writeFile(baseDir + 'verifyDerivedProofValue.json', JSON.stringify(derivedProofValue, null, 2))

  // **Approach Specific Cryptographic Verification**
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
  const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
  const L = numUndisclosed(bbsProof) + msgScalars.length
  const gens = await prepareGenerators(L + 1, API_ID_BBS_SHA) // Generate enough for all messages
  const ph = presentationHeader
  const verified = await proofVerify(pbk, bbsProof, bbsHeader, ph, msgScalars,
    adjSelectedIndexes, gens, API_ID_BBS_SHA)
  console.log(`Derived proof verified: ${verified}`)
}
