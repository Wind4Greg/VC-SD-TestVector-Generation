/*
    Walking through the steps and generating test vectors for creating ("Add")
    a base SHoC proof (Salted Hash of Claims with Merkle tree aggregation)
    for the post-quantum SD cryptosuites. The higher level steps are
    *transformation*, *hashing*, *Merkleization* and *serialization*.

    This has been reordered so that the steps that don't depend on the
    cryptosuite or signature algorithm come first, and their outputs are
    shared by all three suites: the transformation, the salts derived from
    the salt seed, the leaf hashes and the Merkle root.

    Spec sections (VC-Data-Integrity): MerkleizeSD, DeriveSaltsSD, MTH,
    SerializeBase-SHoC.

    The salt seed is fixed (input/SaltSeed.json) so that the test vectors are
    reproducible. The spec requires a fresh random seed for every real proof.
*/

import { repoPath } from '../lib/paths.js';
import { serializeBaseProofValue } from './proofValue.js';
import { deriveSalts, uint64be } from './salts.js';
import { leafHash, mth } from './merkle.js';
import { examples, selectExamples } from '../lib/examples.js';
import { hashingSD, proofConfigCanon, transformSD } from '../lib/sdCommon.js';
import { mkdir, readFile, writeFile } from "fs/promises";
import jsonld from "jsonld";
import { localLoader } from "../lib/documentLoader.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded } from "@noble/post-quantum/falcon.js";
import { klona } from "klona";

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

// SHoC test vectors are only generated for the "employ" example so far
const example = examples[selectExamples(["employ"])[0]];
const dirsAndFiles = {
  outputDir: repoPath('shoc/output/common/employ/'), // For outputs across different signature schemes
  inputFile: example.unsigned,
  mandatoryFile: example.mandatory,
};

// Create output directory for the test vectors
const baseDir = dirsAndFiles.outputDir;
await mkdir(baseDir, { recursive: true });

// HMAC/PRF key material -- Shared between issuer and holder
const keyMaterialHMAC = JSON.parse(
  await readFile(repoPath('input/HMACKey.json')),
);
const hmacKeyString = keyMaterialHMAC.hmacKeyString;
const hmacKey = hexToBytes(hmacKeyString);

// Salt seed -- fixed for reproducible test vectors, see the note above
const { saltSeedString } = JSON.parse(
  await readFile(repoPath('input/SaltSeed.json')),
);
const saltSeed = hexToBytes(saltSeedString);

// Read input document from a file
const document = JSON.parse(
  await readFile(dirsAndFiles.inputFile),
);

// **Transformation Step**

const mandatoryPointers = JSON.parse(
  await readFile(dirsAndFiles.mandatoryFile),
);

// General SD transform, false ==> shuffled label map (not the legacy ECDSA-SD one)
const { mandatory, nonMandatory } = await transformSD(document, mandatoryPointers, hmacKey, false);

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

// **Merkleization Step** (MerkleizeSD)

// The leaves are the non-mandatory statements in canonical order.
const nonMandatoryStatements = [...nonMandatory.values()];
const treeSize = nonMandatoryStatements.length;

// DeriveSaltsSD: salts[i] = HMAC-SHA-256(saltSeed, uint64be(i))[0:16]
const salts = deriveSalts(saltSeed, treeSize);
await writeFile(
  baseDir + "addSalts.json",
  JSON.stringify({
    saltSeed: bytesToHex(saltSeed),
    salts: salts.map((s) => bytesToHex(s)),
  }, null, 2),
);

// Leaf hash j = H(0x00 || salts[j] || UTF-8(nonMandatory[j])), then the
// Merkle Tree Hash over the leaf hashes gives the root that gets signed.
const leafHashes = nonMandatoryStatements.map((statement, j) => leafHash(salts[j], statement));
const merkleRoot = mth(leafHashes);
await writeFile(
  baseDir + "addMerkleData.json",
  JSON.stringify({
    treeSize,
    leafHashes: leafHashes.map((h) => bytesToHex(h)),
    merkleRoot: bytesToHex(merkleRoot),
  }, null, 2),
);
console.log(`treeSize: ${treeSize}, merkleRoot: ${bytesToHex(merkleRoot)}`);

// Signature specific stuff

const testCases = [
  {
    outputDir: repoPath('shoc/output/mldsa44-sd-2024/employ/'),
    keyFile: repoPath('input/KeysMLDSA.json'),
    keyName: "mldsa44",
    suiteName: "mldsa44-sd-2024",
    sigAlg: ml_dsa44,
  },
  {
    outputDir: repoPath('shoc/output/slhdsa128-sd-2024/employ/'),
    keyFile: repoPath('input/KeysSLHDSA.json'),
    keyName: "slh128s",
    suiteName: "slhdsa128-sd-2024",
    sigAlg: slh_dsa_sha2_128s,
  },
  {
    outputDir: repoPath('shoc/output/falcon512-sd-2024/employ/'),
    keyFile: repoPath('input/KeysFALCON.json'),
    keyName: "falcon512",
    suiteName: "falcon512-sd-2024",
    sigAlg: falcon512padded,
  },
];

for (const test of testCases) {
  console.log(`Working on test case: ${test.suiteName}`);
  const baseDir = test.outputDir;
  await mkdir(baseDir, { recursive: true });
  // Obtain key material and process into byte array format
  const keyMaterial = JSON.parse(
    await readFile(test.keyFile),
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
  await writeFile(
    baseDir + "addProofConfig.json",
    JSON.stringify(proofConfig, null, 2),
  );

  const proofCanon = await proofConfigCanon(proofConfig, document, "sha256");
  await writeFile(baseDir + "addProofConfigCanon.txt", proofCanon);

  /* **Hashing Step**
   "The required inputs to this algorithm are a transformed data document (transformedDocument)
   and canonical proof configuration (canonicalProofConfig). A hash data value represented as an
   object is produced as output. " In the SHoC approach the salted hash data
   from MerkleizeSD (saltSeed, treeSize, merkleRoot) is added to it. */

  const { proofHash, mandatoryHash } = hashingSD(mandatory, proofCanon, "sha256");
  const hashData = klona(transformed);
  hashData.proofHash = proofHash;
  hashData.mandatoryHash = mandatoryHash;
  hashData.saltSeed = saltSeed;
  hashData.treeSize = treeSize;
  hashData.merkleRoot = merkleRoot;

  // **SerializeBase-SHoC**
  // toSign = proofHash || mandatoryHash || uint64be(treeSize) || merkleRoot.
  // The salt seed is not signed; the salts are bound to the root through
  // the leaf hashes.
  const toSign = concatBytes(
    hashData.proofHash,
    hashData.mandatoryHash,
    uint64be(hashData.treeSize),
    hashData.merkleRoot,
  );
  // For test vector purposes convert uint8arrays to hex and don't rewrite
  // the transformed information.
  const hashDataOutput = {
    proofHash: bytesToHex(proofHash),
    mandatoryHash: bytesToHex(mandatoryHash),
    treeSize,
    merkleRoot: bytesToHex(merkleRoot),
    toSign: bytesToHex(toSign),
  };
  await writeFile(
    baseDir + "addHashData.json",
    JSON.stringify(hashDataOutput, null, 2),
  );

  // Note that the extraEntropy option makes ML-DSA and SLH-DSA signing
  // deterministic; it may have no effect for Falcon.
  const signature = test.sigAlg.sign(toSign, secretKey, { extraEntropy: false });

  // Components: signature, hmacKey, saltSeed, treeSize, merkleRoot,
  // mandatoryPointers, behind the header bytes 0xd9, 0x5d, 0x12.
  const baseProof = serializeBaseProofValue({
    signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers,
  });
  console.log(`Length of baseProof is ${baseProof.length} characters`);

  // Construct and Write Signed Document
  const signedDocument = klona(document);
  delete proofConfig["@context"];
  signedDocument.proof = proofConfig;
  signedDocument.proof.proofValue = baseProof;
  await writeFile(
    baseDir + "addSignedSDBase.json",
    JSON.stringify(signedDocument, null, 2),
  );
}
