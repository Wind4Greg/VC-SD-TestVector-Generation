/*
    Walking through the steps and generating test vectors for verifying a derived
    PQC-SDH selective disclosure proof using selective disclosure primitive functions.

    Key initialization step: [3.4.9 createVerifyData](https://w3c.github.io/vc-di-ecdsa/#createverifydata)
*/
import { repoPath } from './lib/paths.js';
import { parseDerivedProofValue } from './shoc/proofValue.js';
import {createVerifyData} from './lib/sdCommon.js';
import { mkdir, readFile, writeFile } from "fs/promises";
import jsonld from "jsonld";
import { localLoader } from "./lib/documentLoader.js";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded } from "@noble/post-quantum/falcon.js";
import { klona } from "klona";
import { base64url } from "multiformats/bases/base64";

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

// Helper function for array equality
// Source - https://stackoverflow.com/q/76127214
// Posted by Filip Seman
// Retrieved 2026-04-16, License - CC BY-SA 4.0
function isEqual(arr1, arr2) {
  if (arr1.length !== arr2.length) {
    return false;
  }
  return arr1.every((value, index) => value === arr2[index]);
}

const testCases = [
  {
    suiteName: "mldsa44-sd-2024",
    baseDir: repoPath('output/mldsa44-sd-2024/'),
    sigAlg: ml_dsa44,
  },
  {
    suiteName: "slhdsa128-sd-2024",
    baseDir: repoPath('output/slhdsa128-sd-2024/'),
    sigAlg: slh_dsa_sha2_128s,
  },
  {
    suiteName: "falcon512-sd-2024",
    baseDir: repoPath('output/falcon512-sd-2024/'),
    sigAlg: falcon512padded,
  },
];

for (const test of testCases) {
  // Create output directory for the results
  const baseDir = test.baseDir;
  const status = await mkdir(baseDir, { recursive: true });

  // Read base signed document from a file 'revealDocument.json', 'DBderivedCredential.json'
  const document = JSON.parse(
    await readFile(
      baseDir + "derivedRevealDocument.json",
    ),
  );

  const options = { documentLoader: localLoader };


  const proof = document.proof;
  const proofValue = proof.proofValue;
  
  //  **Parse Derived Proof Value**

  // Checks the header and that the components have the expected types
  let { signature, salts, saltedHashes, compressedLabelMap: labelMapCompressed,
    mandatoryIndexes, selectiveIndexes } = parseDerivedProofValue(proofValue);
  

  // get additional verify data
  const {proofHash, mandatoryHash, nonMandatory} = await createVerifyData(document, labelMapCompressed, mandatoryIndexes, false);

  // **Approach Specific Cryptographic Verification**

  // Get public key
  // console.log(proof.verificationMethod.split("did:key:"));
  //
  const encodedPbk = proof.verificationMethod.split("did:key:")[1];
  // console.log(encodedPbk);
  let pbk = base64url.decode(encodedPbk);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  // console.log(`Public Key hex: ${bytesToHex(pbk)}, Length: ${pbk.length}`)

  /* Initialize toVerify to the result of calling the algorithm in Setion 3.4.1 serializeSignData,
passing proofHash, publicKey, and mandatoryHash.
*/

  const toVerify = concatBytes(
    proofHash,
    mandatoryHash,
    ...saltedHashes,
  );

  // Verify base signature
  const msgHash = sha256(toVerify); // Hash is done outside of the algorithm in noble/curve case.
  let verificationResult = test.sigAlg.verify(signature, msgHash, pbk);
  console.log(`Base Signature verified: ${verificationResult}`);


  const utf8encoder = new TextEncoder(); // To convert utf8 text to Uint8Array

  nonMandatory.forEach((value, index) => {
    let aSaltedHash = sha256(
      concatBytes(salts[index], utf8encoder.encode(value)),
    );
    let shResult = isEqual(aSaltedHash, saltedHashes[selectiveIndexes[index]]);
    console.log(`Salted hash ${index} verified: ${shResult}`);
    verificationResult &&= shResult;
  });

  console.log(`${test.suiteName} Derived document verified: ${verificationResult}`);
}
