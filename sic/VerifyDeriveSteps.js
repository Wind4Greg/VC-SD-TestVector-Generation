/*
    Walking through the steps and generating test vectors for verifying a derived
    selective disclosure proof using selective disclosure primitive functions.

    Reference:

    [3.5.7 Verify Derived Proof (ecdsa-sd-2023)](https://w3c.github.io/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023)

    Key initialization step: [3.4.9 createVerifyData](https://w3c.github.io/vc-di-ecdsa/#createverifydata)
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
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'
import { p256 } from '@noble/curves/p256'
import { klona } from 'klona'
import { base58btc } from 'multiformats/bases/base58'
import { base64url } from 'multiformats/bases/base64'

// Output directory for each supported example; choose examples with --example
const outputDirs = {
  wind: repoPath('sic/output/ecdsa-sd-2023/wind/'),
  employ: repoPath('sic/output/ecdsa-sd-2023/employ/'),
  prc: repoPath('sic/output/ecdsa-sd-2023/prc/')
}

for (const name of selectExamples(Object.keys(outputDirs))) {
  console.log(`*** Example: ${name} ***`)
  await verifyExample(outputDirs[name])
}

async function verifyExample (baseDir) {
  const status = await mkdir(baseDir, { recursive: true })

  jsonld.documentLoader = localLoader // Local loader for JSON-LD

  // Read base signed document from a file 'revealDocument.json', 'DBderivedCredential.json'
  const document = JSON.parse(
    await readFile(
      baseDir + 'derivedRevealDocument.json'
    )
  )

  const options = { documentLoader: localLoader }

  // Parse derived proof
  const proof = document.proof
  const proofValue = proof.proofValue

  // Checks the header and that the components have the expected types and sizes
  let { baseSignature, publicKey, signatures, compressedLabelMap: labelMapCompressed, mandatoryIndexes } =
    parseDerivedProofValue(proofValue)
  publicKey = new Uint8Array(publicKey) // Just to make sure convert into byte array

  // get additional verify data
  const {proofHash, mandatoryHash, nonMandatory} = await createVerifyData(document, labelMapCompressed, mandatoryIndexes, true);

  /* If the length of signatures does not match the length of nonMandatory, throw an error
  indicating that the signature count does not match the non-mandatory message count.
  */
  if (signatures.length !== nonMandatory.length) {
    throw new Error('signature and nonMandatory counts do not match')
  }

  // **Approach Specific Cryptographic Verification**
  /* Initialize publicKeyBytes to the public key bytes expressed in publicKey. Instructions on
  how to decode the public key value can be found in Section 2.1.1 Multikey.
  **ISSUE**: Which public key? ==> non-ephemeral key from issuer
  */
  // Get public key
  console.log(proof.verificationMethod.split('did:key:'))
  //
  const encodedPbk = proof.verificationMethod.split('did:key:')[1].split('#')[0]
  console.log(encodedPbk)
  let pbk = base58btc.decode(encodedPbk)
  pbk = pbk.slice(2, pbk.length) // First two bytes are multi-format indicator
  console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)

  /* Initialize toVerify to the result of calling the algorithm in Setion 3.4.1 serializeSignData,
  passing proofHash, publicKey, and mandatoryHash.
  */
  const toVerify = concatBytes(proofHash, publicKey, mandatoryHash)

  /* Initialize verificationResult be the result of applying the verification algorithm of the
  Elliptic Curve Digital Signature Algorithm (ECDSA) [FIPS-186-5], with toVerify as the data to
  be verified against the baseSignature using the public key specified by publicKeyBytes.
  If verificationResult is false, return false.
  */
  // Verify base signature
  const msgHash = sha256(toVerify) // Hash is done outside of the algorithm in noble/curve case.
  let verificationResult = p256.verify(baseSignature, msgHash, pbk)
  console.log(`Base Signature verified: ${verificationResult}`)

  /* For every entry (index, signature) in signatures, verify every signature for every
  selectively disclosed (non-mandatory) statement:

      Initialize verificationResult to the result of applying the verification algorithm
      Elliptic Curve Digital Signature Algorithm (ECDSA) [FIPS-186-5], with the UTF-8
      representation of the value at index of nonMandatory as the data to be verified
      against signature using the public key specified by publicKeyBytes.
      If verificationResult is false, return false.

      **ISSUE**: this uses the ephemeral public key recovered from the CBOR encoding
      above and not the public key just used on the base signature.
  */

  const ephemeralPubKey = publicKey.slice(2)
  nonMandatory.forEach(function (quad, index) {
    const msgHash = sha256(quad) // Hash is done outside of the algorithm in noble/curve case.
    const sigVerified = p256.verify(signatures[index], msgHash, ephemeralPubKey)
    console.log(`Non Mandatory Signature ${index} verified: ${sigVerified}`)
    verificationResult &&= sigVerified
  })

  console.log(`Derived document verified: ${verificationResult}`)
}
