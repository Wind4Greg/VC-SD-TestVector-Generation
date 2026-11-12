/*
    Walking through the steps and generating test vectors for verifying a derived
    PQC-SDH selective disclosure proof using selective disclosure primitive functions.

    Key initialization step: [3.4.9 createVerifyData](https://w3c.github.io/vc-di-ecdsa/#createverifydata)
*/
import { repoPath } from './lib/paths.js';
import {createVerifyData} from './CommonAlgs.js';
import { mkdir, readFile, writeFile } from "fs/promises";
import jsonld from "jsonld";
import { localLoader } from "./documentLoader.js";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded } from "@noble/post-quantum/falcon.js";
import { klona } from "klona";
import { decode as decodeCbor } from "cbor2";
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

  if (!proofValue.startsWith("u")) {
    throw new Error("proofValue not a valid multibase-64-url encoding");
  }
  const decodedProofValue = base64url.decode(proofValue);
  // check header bytes are: 0xd9, 0x5d, and 0x11
  if (
    decodedProofValue[0] !== 0xd9 ||
    decodedProofValue[1] !== 0x5d ||
    decodedProofValue[2] !== 0x11
  ) {
    throw new Error("Invalid proofValue header");
  }
  const decodeThing = decodeCbor(decodedProofValue.slice(3));
  if (decodeThing.length !== 6) {
    throw new Error("Bad length of CBOR decoded proofValue data");
  }
  // console.log(decodeThing);
  let [
    signature,
    salts,
    saltedHashes,
    labelMapCompressed,
    mandatoryIndexes,
    selectiveIndexes,
  ] = decodeThing;

  if (!(labelMapCompressed instanceof Map)) {
    throw new Error("Bad label map in proofValue");
  }
  // Using shuffle labeling, just an integer
  labelMapCompressed.forEach(function (value, key) {
    if (!Number.isInteger(key) || !Number.isInteger(value)) {
      throw new Error('Bad key or value in compress label map in proofValue')
    }
  })

  if (!Array.isArray(mandatoryIndexes)) {
    throw new Error("mandatory indexes is not an array in proofValue");
  }
  mandatoryIndexes.forEach((value) => {
    if (!Number.isInteger(value)) {
      throw new Error("Value in mandatory indexes  is not an integer");
    }
  });
  

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
