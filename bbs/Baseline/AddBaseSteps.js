/*
    Walking through my steps and generating test vectors for  creating
    a base BBS proof using selective disclosure primitive functions. The higher
    level steps are *transformation*, *hashing*, and *serialization*.
*/
import { repoPath } from '../../lib/paths.js'
import { serializeBaseProofValue } from '../proofValue.js'
import { examples, selectExamples } from '../../lib/examples.js'
import { hashingSD, proofConfigCanon, transformSD} from '../../lib/sdCommon.js'
import { mkdir, readFile, writeFile } from 'fs/promises'
import jsonld from 'jsonld'
import { localLoader } from '../../lib/documentLoader.js'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { API_ID_BBS_SHA, messages_to_scalars as msgsToScalars, prepareGenerators, sign } from '../lib/BBS.js'
import { klona } from 'klona'
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64'

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

// Output directory for each supported example; choose examples with --example
const outputDirs = {
  wind: repoPath('bbs/output/Baseline/wind/'),
  prc: repoPath('bbs/output/Baseline/prc/')
}

for (const name of selectExamples(Object.keys(outputDirs))) {
  console.log(`*** Example: ${name} ***`)
  await generate(examples[name], outputDirs[name])
}

async function generate (example, baseDir) {
  await mkdir(baseDir, { recursive: true })

  jsonld.documentLoader = localLoader // Local loader for JSON-LD

  // Read input document from a file either treeDoc.json or windDoc.json
  const document = JSON.parse(
    await readFile(example.unsigned))

  // Obtain key material and process into byte array format
  const keyMaterial = JSON.parse(
    await readFile(repoPath('input/BBSKeyMaterial.json')))
  // HMAC/PRF key material -- Shared between issuer and holder
  const hmacKeyString = keyMaterial.hmacKeyString
  const hmacKey = hexToBytes(hmacKeyString)
  // Sample long term issuer signing key
  const privateKey = hexToBytes(keyMaterial.privateKeyHex)
  const publicKey = hexToBytes(keyMaterial.publicKeyHex)
  // BLS12-381 G2 public key prefix 0xeb01
  const publicKeyMultibase = base58btc.encode(concatBytes(new Uint8Array([0xeb, 0x01]), publicKey))

  const options = { documentLoader: localLoader }

  // Missing Step: **Proof Configuration Options**
  // Set proof options per draft
  const proofOptions = {}
  proofOptions.type = 'DataIntegrityProof'
  proofOptions.cryptosuite = 'bbs-2023'
  proofOptions.created = '2023-08-15T23:36:38Z'
  proofOptions.verificationMethod = 'did:key:' + publicKeyMultibase + '#' + publicKeyMultibase
  proofOptions.proofPurpose = 'assertionMethod'
  proofOptions['@context'] = document['@context']
  await writeFile(baseDir + 'addProofConfig.json', JSON.stringify(proofOptions, null, 2))

  const proofCanon = await proofConfigCanon(proofOptions, document, "sha256")
  await writeFile(baseDir + 'addProofConfigCanon.txt', proofCanon)

  const mandatoryPointers = JSON.parse(
    await readFile(
      example.mandatory
    )
  )

  // **Transformation Step**
  // General SD transform, note  false ==> don't use legacy ECDSA-SD label map
  const {mandatory, nonMandatory} = await transformSD(document, mandatoryPointers, hmacKey, false);
  const transformed = { mandatoryPointers, mandatory, nonMandatory, hmacKey }
  // Converting maps to arrays of entries for test vector production not required
  // for algorithm.
  const transformOutput = { mandatoryPointers, mandatory, nonMandatory, hmacKeyString }
  await writeFile(baseDir + 'addBaseTransform.json', JSON.stringify(transformOutput, replacerMap, 2))

  // For illustration purposes only show the canonicalized document nquads
  // const documentCanonQuads = await jsonld.canonize(document) // block of text
  // const documentCanon = documentCanonQuads.split('\n').slice(0, -1).map(q => q + '\n') // array
  // await writeFile(baseDir + 'addBaseDocCanon.json', JSON.stringify(documentCanon, null, 2))
  // await writeFile(baseDir + 'addBaseDocHMACCanon.json', JSON.stringify(stuff.nquads, null, 2))

  // **Hashing Step**
  const {proofHash, mandatoryHash} = hashingSD(mandatory, proofCanon, "sha256");

  const hashData = klona(transformed)
  hashData.proofHash = proofHash
  hashData.mandatoryHash = mandatoryHash
  // For test vector purposes convert maps to arrays of pairs and uint8arrays to hex
  // and don't rewrite the transformed information.
  const hashDataOutput = {}
  hashDataOutput.proofHash = bytesToHex(proofHash)
  hashDataOutput.mandatoryHash = bytesToHex(mandatoryHash)
  await writeFile(baseDir + 'addHashData.json', JSON.stringify(hashDataOutput, null, 2))

  /* Create BBS signature */
  const bbsHeader = concatBytes(proofHash, mandatoryHash)
  const te = new TextEncoder()
  const bbsMessages = [...nonMandatory.values()].map(txt => te.encode(txt)) // must be byte arrays
  const msgScalars = await msgsToScalars(bbsMessages, API_ID_BBS_SHA)
  const gens = await prepareGenerators(bbsMessages.length + 1, API_ID_BBS_SHA)
  const bbsSignature = await sign(privateKey, publicKey, bbsHeader, msgScalars, gens, API_ID_BBS_SHA)
  console.log(`BBS signature: ${bytesToHex(bbsSignature)}`)

  const rawBaseSignatureInfo = {
    bbsSignature: bytesToHex(bbsSignature),
    mandatoryPointers
  }
  // console.log(rawBaseSignatureInfo);
  await writeFile(baseDir + 'addRawBaseSignatureInfo.json', JSON.stringify(rawBaseSignatureInfo, null, 2))

  // CBOR-encode components and append it to proofValue.
  // bbsSignature, bbsHeader, publicKey, hmacKey, and mandatoryPointers

  const baseProof = serializeBaseProofValue({
    bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers
  })
  console.log(baseProof)
  console.log(`Length of baseProof is ${baseProof.length} characters`)

  // Construct and Write Signed Document
  const signedDocument = klona(document)
  delete proofOptions['@context']
  signedDocument.proof = proofOptions
  signedDocument.proof.proofValue = baseProof
  console.log(JSON.stringify(signedDocument, null, 2))
  await writeFile(baseDir + 'addSignedSDBase.json', JSON.stringify(signedDocument, null, 2))
}
