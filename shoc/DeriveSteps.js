/*
    Walking through the steps and generating test vectors for the create a PQC-SD
    **derived** selective disclosure proof using selective disclosure common 
    algorithms.
*/

import { repoPath } from '../lib/paths.js';
import { parseBaseProofValue, serializeDerivedProofValue } from './proofValue.js';
import { examples, selectExamples } from '../lib/examples.js';
import { mkdir, readFile, writeFile } from "fs/promises";
import {createDisclosureData} from '../lib/sdCommon.js';
import jsonld from "jsonld";
import { localLoader } from "../lib/documentLoader.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
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

// PQC-SD test vectors are only generated for the "employ" example so far
const example = examples[selectExamples(["employ"])[0]];
const dirsAndFiles = {
  selectFile: example.selective,
};

const testCases = [
  {
    suiteName: "mldsa44-sd-2024",
    baseDir: repoPath('shoc/output/mldsa44-sd-2024/employ/'),
  },
  {
    suiteName: "slhdsa128-sd-2024",
    baseDir: repoPath('shoc/output/slhdsa128-sd-2024/employ/'),
  },
  {
    suiteName: "falcon512-sd-2024",
    baseDir: repoPath('shoc/output/falcon512-sd-2024/employ/'),
  },
];

const selectivePointers = JSON.parse(
  await readFile(dirsAndFiles.selectFile),
);

for (const test of testCases) {
  console.log(`Starting SD-Derive for ${test.suiteName}`);
  // Create output directory for the test vectors
  const baseDir = test.baseDir;
  await mkdir(baseDir, { recursive: true });

  // Read base signed document from a file
  const document = JSON.parse(
    await readFile(baseDir + "addSignedSDBase.json"),
  );

  const options = { documentLoader: localLoader };

  /* Initialize signature, hmacKey, salts, saltedHashes, and mandatoryPointers to the
values of the associated properties in the object returned when calling the algorithm
parseBaseProofValue, passing the proofValue from proof. */

  // parseBaseProofValue:
  const proof = document.proof;
  delete document.proof; // IMPORTANT: all work uses document without proof
  const { signature, hmacKey, salts, saltedHashes, mandatoryPointers } =
    parseBaseProofValue(proof.proofValue);
  const baseProofData = {
    signature: bytesToHex(signature),
    hmacKey: bytesToHex(hmacKey),
    salts: salts.map((s) => bytesToHex(s)),
    saltedHashes: saltedHashes.map((sh) => bytesToHex(sh)),
    mandatoryPointers,
  };
  await writeFile(
    baseDir + "derivedRecoveredBaseData.json",
    JSON.stringify(baseProofData, replacerMap, 2),
  );

  /* Create Disclosure Data */

  const {revealDocument, mandatoryIndexes, selectiveIndexes, verifierLabelMap, 
    mandatory, nonMandatory} = await createDisclosureData(document, 
    mandatoryPointers, selectivePointers, hmacKey, false);

  const filteredSalts = salts.filter((value, index) => selectiveIndexes.includes(index))

  await writeFile(
    baseDir + "derivedUnsignedReveal.json",
    JSON.stringify(revealDocument, replacerMap, 2),
  );

  const groupIndexes = {
    // combinedIndexes,
    mandatoryIndexes,
    // nonMandatoryIndexes,
    selectiveIndexes,
  };
  await writeFile(
    baseDir + "derivedGroupIndexes.json",
    JSON.stringify(groupIndexes, replacerMap),
  );

  const disclosureData = {
    signature: bytesToHex(signature),
    filteredSalts: filteredSalts.map((s) => bytesToHex(s)),
    saltedHashes: saltedHashes.map((sh) => bytesToHex(sh)),
    labelMap: verifierLabelMap,
    mandatoryIndexes,
    selectiveIndexes,
  };
  await writeFile(
    baseDir + "derivedDisclosureData.json",
    JSON.stringify(disclosureData, replacerMap, 2),
  );

  // Initialize newProof to a shallow copy of proof.
  const newProof = Object.assign({}, proof);





  const derivedProofValueString = serializeDerivedProofValue({
    signature, salts: filteredSalts, saltedHashes, labelMap: verifierLabelMap,
    mandatoryIndexes, selectiveIndexes,
  });
  // console.log(derivedProofValueString)
  console.log(
    `Length of derivedProofValue is ${derivedProofValueString.length} characters`,
  );
  /*  Replace proofValue in newProof with the result of calling the algorithm in Section 3.4.7
  serializeDerivedProofValue, passing baseSignature, publicKey, signatures, labelMap, and mandatoryIndexes.
  Set the value of the "proof" property in revealDocument to newProof.
  Return revealDocument as the selectively revealed document. */
  newProof.proofValue = derivedProofValueString;
  revealDocument.proof = newProof;
  // console.log(JSON.stringify(revealDocument, null, 2));
  await writeFile(
    baseDir + "derivedRevealDocument.json",
    JSON.stringify(revealDocument, null, 2),
  );
}
