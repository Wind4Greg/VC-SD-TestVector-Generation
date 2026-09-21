/*
    Walking through the steps and generating test vectors for the create a PQC-SD
    **derived** selective disclosure proof using selective disclosure common 
    algorithms.
*/

import { mkdir, readFile, writeFile } from "fs/promises";
import {createDisclosureData} from './CommonAlgs.js';
import jsonld from "jsonld";
import { localLoader } from "./documentLoader.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
import { decode as decodeCbor, encode as encodeCbor } from "cbor2";
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

const dirsAndFiles = {
  selectFile: "./input/employSelective.json",
};

const testCases = [
  {
    suiteName: "mldsa44-sd-2024",
    baseDir: "./output/mldsa44-sd-2024/",
  },
  {
    suiteName: "slhdsa128-sd-2024",
    baseDir: "./output/slhdsa128-sd-2024/",
  },
  {
    suiteName: "falcon512-sd-2024",
    baseDir: "./output/falcon512-sd-2024/",
  },
];

const selectivePointers = JSON.parse(
  await readFile(new URL(dirsAndFiles.selectFile, import.meta.url)),
);

for (const test of testCases) {
  console.log(`Starting SD-Derive for ${test.suiteName}`);
  // Create output directory for the test vectors
  const baseDir = test.baseDir;
  await mkdir(baseDir, { recursive: true });

  // Read base signed document from a file
  const document = JSON.parse(
    await readFile(new URL(baseDir + "addSignedSDBase.json", import.meta.url)),
  );

  const options = { documentLoader: localLoader };

  /* Initialize signature, hmacKey, salts, saltedHashes, and mandatoryPointers to the
values of the associated properties in the object returned when calling the algorithm
parseBaseProofValue, passing the proofValue from proof. */

  // parseBaseProofValue:
  const proof = document.proof;
  delete document.proof; // IMPORTANT: all work uses document without proof
  const proofValue = proof.proofValue; // base64url encoded
  const proofValueBytes = base64url.decode(proofValue);
  // console.log(proofValueBytes.length);
  // check header bytes are: 0xd9, 0x5d, and 0x10
  if (
    proofValueBytes[0] !== 0xd9 ||
    proofValueBytes[1] !== 0x5d ||
    proofValueBytes[2] !== 0x10
  ) {
    throw new Error("Invalid proofValue header");
  }
  const decodeThing = decodeCbor(proofValueBytes.slice(3));
  if (decodeThing.length !== 5) {
    throw new Error("Bad length of CBOR decoded proofValue data");
  }
  const [signature, hmacKey, salts, saltedHashes, mandatoryPointers] =
    decodeThing;
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



  const compressLabelMap = new Map()
  verifierLabelMap.forEach(function (v, k) {
    const key = parseInt(k.split('c14n')[1])
    const value = parseInt(v.split('b')[1])
    compressLabelMap.set(key, value)
  })

  let derivedProofValue = new Uint8Array([0xd9, 0x5d, 0x11]);
  const components = [
    signature,
    filteredSalts,
    saltedHashes,
    compressLabelMap,
    mandatoryIndexes,
    selectiveIndexes,
  ];
  const cborThing = encodeCbor(components);
  derivedProofValue = concatBytes(derivedProofValue, cborThing);
  const derivedProofValueString = base64url.encode(derivedProofValue);
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
  writeFile(
    baseDir + "derivedRevealDocument.json",
    JSON.stringify(revealDocument, null, 2),
  );
}
