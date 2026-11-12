/*
    Walking through the steps and generating test vectors for verifying a derived
    BBS selective disclosure proof using selective disclosure primitive functions.
*/

import { repoPath } from '../lib/paths.js';
import { parseDerivedProofValue } from './proofValue.js';
import { selectExamples } from '../lib/examples.js';
import {createVerifyData} from '../lib/sdCommon.js';
import { mkdir, readFile, writeFile } from 'fs/promises'
import { createLabelMapFunction, labelReplacementCanonicalizeJsonLd } from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from '../lib/documentLoader.js'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { klona } from 'klona'
import { base58btc } from 'multiformats/bases/base58'
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
  // Checks the header and that the components have the expected types
  const { bbsProof, compressedLabelMap: labelMapCompressed, mandatoryIndexes,
    selectiveIndexes: adjSelectedIndexes, presentationHeader } = parseDerivedProofValue(proofValue)

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
