/*
    Walking through the steps and generating test vectors for the create a
    **derived** selective disclosure proof using selective disclosure primitive
    functions.

    Reference:

    [Add Derived Proof (ecdsa-sd-2023)](https://w3c.github.io/vc-di-ecdsa/#add-derived-proof-ecdsa-sd-2023)

    Key steps:
    1. [createDisclosureData](https://w3c.github.io/vc-di-ecdsa/#createdisclosuredata)
    2. [serializeDerivedProofValue](https://w3c.github.io/vc-di-ecdsa/#serializederivedproofvalue)
*/
import { repoPath } from './lib/paths.js';
import { parseBaseProofValue, serializeDerivedProofValue } from './sic/proofValue.js';
import { examples, selectExamples } from './lib/examples.js';
import {createDisclosureData} from './lib/sdCommon.js';
import { mkdir, readFile, writeFile } from 'fs/promises'
import jsonld from 'jsonld'
import { localLoader } from './lib/documentLoader.js'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
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
  wind: repoPath('output/ecdsa-sd-2023/'),
  employ: repoPath('output/ecdsa-sd-2023/employ/'),
  prc: repoPath('output/ecdsa-sd-2023/prc/')
}

for (const name of selectExamples(Object.keys(outputDirs))) {
  console.log(`*** Example: ${name} ***`)
  await generate(examples[name], outputDirs[name])
}

async function generate (example, baseDir) {
  await mkdir(baseDir, { recursive: true })

  // Chosen to be tricky as mandatory has "/boards/0/year" and we are going to
  // reveal all about board 0
  const selectivePointers = JSON.parse(
    await readFile(
      example.selective
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

  // **Parse Base Proof**
  const proof = document.proof
  delete document.proof // IMPORTANT: all work uses document without proof
  const { baseSignature, publicKey: proofPublicKey, hmacKey, signatures, mandatoryPointers } =
    parseBaseProofValue(proof.proofValue)
  const baseProofData = {
    baseSignature: bytesToHex(baseSignature),
    proofPublicKey: base58btc.encode(proofPublicKey),
    hmacKey: bytesToHex(hmacKey),
    signatures: signatures.map(sig => bytesToHex(sig)),
    mandatoryPointers
  }
  await writeFile(baseDir + 'derivedRecoveredBaseData.json', JSON.stringify(baseProofData, replacerMap, 2))

  /* Create Disclosure Data */

  const {revealDocument, mandatoryIndexes, selectiveIndexes, verifierLabelMap, 
    mandatory, nonMandatory} = await createDisclosureData(document, 
      mandatoryPointers, selectivePointers, hmacKey, true);

  // console.log("verifierLabelMap:");
  // console.log(verifierLabelMap);

  await writeFile(baseDir + 'derivedUnsignedReveal.json', JSON.stringify(revealDocument, replacerMap, 2))

  const filteredSignatures = signatures.filter((value, index) => selectiveIndexes.includes(index))
  await writeFile(baseDir + 'derivedAdjSignatures.json',
    JSON.stringify({ adjSignatureIndexes:selectiveIndexes, filteredSignatures: filteredSignatures.map(s => bytesToHex(s)) }))

  /* Return an object with properties matching baseSignature, publicKey, "signatures" for filteredSignatures,
  "verifierLabelMap" for labelMap, mandatoryIndexes, and revealDocument.
    **End** of the *createDisclosureData* function
  */
  const disclosureData = {
    baseSignature: bytesToHex(baseSignature),
    publicKey: base58btc.encode(proofPublicKey),
    signatures: filteredSignatures.map(sig => bytesToHex(sig)),
    labelMap: verifierLabelMap,
    mandatoryIndexes: mandatoryIndexes
  }
  await writeFile(baseDir + 'derivedDisclosureData.json', JSON.stringify(disclosureData, replacerMap, 2))

  // Initialize newProof to a shallow copy of proof.
  const newProof = Object.assign({}, proof)
  /* 3.4.7 serializeDerivedProofValue
    The following algorithm serializes a derived proof value. The required inputs are a base signature
    (baseSignature), public key (publicKey), an array of signatures (signatures), a label map (labelMap),
    and an array of mandatory indexes (mandatoryIndexes). A single derived proof value, serialized as a byte string,
    is produced as output.
  */
  /* Initialize compressedLabelMap to the result of calling the algorithm in Section 3.4.5
    compressLabelMap, passing labelMap as the parameter.
  */
  /*  The following algorithm compresses a label map. The required inputs are label map (labelMap).
      The output is a compressed label map.

      Initialize map to an empty map.
      For each entry (k, v) in labelMap:
          Add an entry to map with a key that is a base-10 integer parsed from the characters following
          the "c14n" prefix in k and a value that is a byte array resulting from base64url-no-pad-decoding
          the characters after the "u" prefix in v.
      Return map as compressed label map.
  */


  /*  Initialize a byte array, proofValue, that starts with the ECDSA-SD disclosure proof header
    bytes 0xd9, 0x5d, and 0x01.
    Initialize components to an array with five elements containing the values of: baseSignature,
    publicKey, signatures, compressedLabelMap, and mandatoryIndexes.
    CBOR-encode components and append it to proofValue.
    Return the derived proof as a string with the multibase-base64url-no-pad-encoding of proofValue.
    That is, return a string starting with "u" and ending with the base64url-no-pad-encoded value of proofValue.
  */
  const derivedProofValueString = serializeDerivedProofValue({
    baseSignature, publicKey: proofPublicKey, signatures: filteredSignatures,
    labelMap: verifierLabelMap, mandatoryIndexes
  })
  // console.log(derivedProofValueString)
  // console.log(`Length of derivedProofValue is ${derivedProofValueString.length} characters`)
  /*  Replace proofValue in newProof with the result of calling the algorithm in Section 3.4.7
    serializeDerivedProofValue, passing baseSignature, publicKey, signatures, labelMap, and mandatoryIndexes.
    Set the value of the "proof" property in revealDocument to newProof.
    Return revealDocument as the selectively revealed document. */
  newProof.proofValue = derivedProofValueString
  revealDocument.proof = newProof
  // console.log(JSON.stringify(revealDocument, null, 2));
  await writeFile(baseDir + 'derivedRevealDocument.json', JSON.stringify(revealDocument, null, 2))
}
