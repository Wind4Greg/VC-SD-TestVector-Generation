/*
    Walking through the steps and generating test vectors for  creating ("Add")
    a base PQC-SD proof using selective disclosure primitive functions and 
    salted hash approach. The higher level steps are *transformation*, 
    *hashing*, and *serialization*.

    This has been slightly reordered so that procedures that are independent of
    a particular ciphersuite name or signature algorithm occur first. So that  
    those outputs can be shared rather than repeated, e.g., salts and salted 
    hashes.


*/

import { hashingSD, proofConfigCanon, saltedHashingSD, transformSD} from './CommonAlgs.js'
import { mkdir, readFile, writeFile } from "fs/promises";
import jsonld from "jsonld";
import { localLoader } from "./documentLoader.js";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded } from "@noble/post-quantum/falcon.js";
import { klona } from "klona";
import { encode as encodeCbor } from "cbor2";
import { base64url } from "multiformats/bases/base64";

// For serialization of JavaScript Map via JSON
function replacerMap(key, value) {
  // See https://stackoverflow.com/questions/29085197/how-do-you-json-stringify-an-es6-map
  if (value instanceof Map) {
    return {
      dataType: "Map",
      value: Array.from(value.entries()), // or with spread: value: [...value]
    };
  } else {
    return value;
  }
}

jsonld.documentLoader = localLoader; // Local loader for JSON-LD
const utf8encoder = new TextEncoder(); // To convert utf8 text to Uint8Array

// Set input file and output directory here
const dirsAndFiles = {
  outputDir: "./output/pqc-sd/", // For outputs across different signature schemes
  inputFile: "./input/employmentAuth.json",
  mandatoryFile: "./input/employMandatory.json",
};

// Create output directory for the test vectors
const baseDir = dirsAndFiles.outputDir;
await mkdir(baseDir, { recursive: true });

// HMAC/PRF key material -- Shared between issuer and holder
const keyMaterialHMAC = JSON.parse(
  await readFile(new URL("./input/HMACKey.json", import.meta.url)),
);
const hmacKeyString = keyMaterialHMAC.hmacKeyString;
const hmacKey = hexToBytes(hmacKeyString);

// Read input document from a file
const document = JSON.parse(
  await readFile(new URL(dirsAndFiles.inputFile, import.meta.url)),
);


// **Transformation Step**

const mandatoryPointers = JSON.parse(
  await readFile(new URL(dirsAndFiles.mandatoryFile, import.meta.url)),
);

// General SD transform, note  true ==> legacy ECDSA-SD label map
const {mandatory, nonMandatory} = await transformSD(document, mandatoryPointers, hmacKey, false);

// As output the transformation algorithm wants us to return an object with
// "mandatoryPointers" set to mandatoryPointers, "mandatory" set to mandatory,
// "nonMandatory" set to nonMandatory, and "hmacKey" set to hmacKey.
const transformed = { mandatoryPointers, mandatory, nonMandatory, hmacKey };
// Converting maps to arrays of entries for test vector production not required
// for algorithm.
const transformOutput = {
  mandatoryPointers,
  mandatory,
  nonMandatory,
  hmacKeyString,
};
await writeFile(
  baseDir + "addBaseTransform.json",
  JSON.stringify(transformOutput, replacerMap, 2),
);

//  Create salted hash array consisting of random salts (32 bytes for 256 bits or
//  16 bytes for 128 bits) and salted hashes of (salt concatenated with non-mandatory value)
//  SD-JWT currently uses 128 bits: https://www.rfc-editor.org/rfc/rfc9901.html#section-4.2.1
//  So I'll just use 16 bytes too.

const {salts, saltedHashes} = saltedHashingSD(nonMandatory, "sha256");
let saltedHashInfo = {
  salts: salts.map((s) => bytesToHex(s)),
  saltedHashes: saltedHashes.map((sh) => bytesToHex(sh)),
};
writeFile(
  baseDir + "addSaltedHashes.json",
  JSON.stringify(saltedHashInfo, null, 2),
);

// Signature specific  stuff

const testCases = [
  {
    outputDir: "./output/mldsa44-sd-2024/",
    keyFile: "./input/KeysMLDSA.json",
    keyName: "mldsa44",
    suiteName: "mldsa44-sd-2024",
    sigAlg: ml_dsa44,
  },
  {
    outputDir: "./output/slhdsa128-sd-2024/",
    keyFile: "./input/KeysSLHDSA.json",
    keyName: "slh128s",
    suiteName: "slhdsa128-sd-2024",
    sigAlg: slh_dsa_sha2_128s,
  },
  {
    outputDir: "./output/falcon512-sd-2024/",
    keyFile: "./input/KeysFALCON.json",
    keyName: "falcon512",
    suiteName: "falcon512-sd-2024",
    sigAlg: falcon512padded,
  },
];

for (const test of testCases) {
  console.log("Working on test case: ${test.suiteName}");
  const baseDir = test.outputDir;
  await mkdir(baseDir, { recursive: true });
  // Obtain key material and process into byte array format
  const keyMaterial = JSON.parse(
    await readFile(new URL(test.keyFile, import.meta.url)),
  );
  // **Proof Configuration Options**
  // Set proof options per draft
  // Proof Configuration Step
  // Sample long term issuer signing key
  const secretKey = hexToBytes(keyMaterial[test.keyName].secretKeyHex);
  const publicKeyMultibase = keyMaterial[test.keyName].publicKeyMultibase;
  const proofConfig = {};
  proofConfig.type = "DataIntegrityProof";
  proofConfig.cryptosuite = test.suiteName;
  proofConfig.created = "2026-04-15T23:36:38Z";
  proofConfig.verificationMethod = "did:key:" + publicKeyMultibase;
  proofConfig.proofPurpose = "assertionMethod";
  proofConfig["@context"] = document["@context"];
  writeFile(
    baseDir + "addProofConfig.json",
    JSON.stringify(proofConfig, null, 2),
  );

  const proofCanon = await proofConfigCanon(proofConfig, document, "sha256") 
  writeFile(baseDir + "addProofConfigCanon.txt", proofCanon);

  /* **Hashing Step**
   "The required inputs to this algorithm are a transformed data document (transformedDocument)
   and canonical proof configuration (canonicalProofConfig). A hash data value represented as an
   object is produced as output. " */

  const {proofHash, mandatoryHash} = hashingSD(mandatory, proofCanon, "sha256");
  // Initialize hashData as a deep copy of transformedDocument and add proofHash as
  // "proofHash" and mandatoryHash as "mandatoryHash" to that object.
  const hashData = klona(transformed);
  hashData.proofHash = proofHash;
  hashData.mandatoryHash = mandatoryHash;
  // For test vector purposes convert maps to arrays of pairs and uint8arrays to hex
  // and don't rewrite the transformed information.
  const hashDataOutput = {};
  hashDataOutput.proofHash = bytesToHex(proofHash);
  hashDataOutput.mandatoryHash = bytesToHex(mandatoryHash);
  writeFile(
    baseDir + "addHashData.json",
    JSON.stringify(hashDataOutput, null, 2),
  );

  // **NEW** produce a PQC signature over the concatenation of proofHash, mandatoryHash, saltedHashes
  const bigConcatenation = concatBytes(
    proofHash,
    mandatoryHash,
    ...saltedHashes,
  );
  const hashBigConcat = sha256(bigConcatenation);
  // Note that the extraEntropy option may only be valid for ML-DSA and SLH-DSA
  let signature = test.sigAlg.sign(hashBigConcat, secretKey, {extraEntropy: false});

  // /* 3.4.2 **MODIFIED** serializeBaseProofValue
  // The following algorithm serializes the base proof value, including the signature,
  // HMAC key, salts, salted  hashes, and mandatory pointers. The required inputs are the signature,
  // an HMAC key hmacKey, an array of salts, an array of salted hashes and an array of mandatoryPointers.
  // A single base proof string value is produced as output.

  // Initialize a byte array, proofValue, that starts with the ECDSA-SD base proof header bytes 0xd9, 0x5d, and 0x00.

  // Initialize components to an array with five elements containing the values of: signature, hmacKey,
  //  salts, saltedHashes, and mandatoryPointers.

  // CBOR-encode components and append it to proofValue.

  // Initialize baseProof to a string with the multibase-base64url-no-pad-encoding of proofValue. That is, return a
  //  string starting with "u" and ending with the base64url-no-pad-encoded value of proofValue.
  // Return baseProof as base proof.
  // */
  let proofValue = new Uint8Array([0xd9, 0x5d, 0x10]); // Header value from spec
  console.log(salts);
  console.log(saltedHashes);
  const components = [
    signature,
    hmacKey,
    salts,
    saltedHashes,
    mandatoryPointers,
  ];
  const cborThing = encodeCbor(components);
  proofValue = concatBytes(proofValue, cborThing);
  const baseProof = base64url.encode(proofValue);
  // console.log(baseProof)
  console.log(`Length of baseProof is ${baseProof.length} characters`);

  // Construct and Write Signed Document
  const signedDocument = klona(document);
  delete proofConfig["@context"];
  signedDocument.proof = proofConfig;
  signedDocument.proof.proofValue = baseProof;
  console.log(JSON.stringify(signedDocument, null, 2));
  writeFile(
    baseDir + "addSignedSDBase.json",
    JSON.stringify(signedDocument, null, 2),
  );
}
