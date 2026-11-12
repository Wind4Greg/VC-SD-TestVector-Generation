/*
    Walking through the steps and generating test vectors for creating a SHoC
    **derived** selective disclosure proof using the selective disclosure
    common algorithms.

    The holder derives all the salts from the base proof's salt seed,
    recomputes every leaf hash from the non-mandatory statements, and builds a
    subtree proof for the disclosed leaves. Only the disclosed leaves' salts
    go into the derived proof; the salt seed never does.

    Spec sections (VC-Data-Integrity): ParseBase-SHoC, DeriveSaltsSD,
    CreateSubtreeProof, SerializeDerived-SHoC.
*/

import { repoPath } from '../lib/paths.js';
import { parseBaseProofValue, serializeDerivedProofValue } from './proofValue.js';
import { deriveSalts } from './salts.js';
import { createSubtreeProof, leafHash, mth, subtreeProofNames } from './merkle.js';
import { examples, selectExamples } from '../lib/examples.js';
import { mkdir, readFile, writeFile } from "fs/promises";
import { createDisclosureData } from '../lib/sdCommon.js';
import jsonld from "jsonld";
import { localLoader } from "../lib/documentLoader.js";
import { bytesToHex } from "@noble/hashes/utils";

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

  // **ParseBase-SHoC**
  const proof = document.proof;
  delete document.proof; // IMPORTANT: all work uses document without proof
  const { signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers } =
    parseBaseProofValue(proof.proofValue);
  const baseProofData = {
    signature: bytesToHex(signature),
    hmacKey: bytesToHex(hmacKey),
    saltSeed: bytesToHex(saltSeed),
    treeSize,
    merkleRoot: bytesToHex(merkleRoot),
    mandatoryPointers,
  };
  await writeFile(
    baseDir + "derivedRecoveredBaseData.json",
    JSON.stringify(baseProofData, null, 2),
  );

  /* Create Disclosure Data */

  const { revealDocument, mandatoryIndexes, selectiveIndexes, verifierLabelMap,
    nonMandatory } = await createDisclosureData(document,
    mandatoryPointers, selectivePointers, hmacKey, false);

  await writeFile(
    baseDir + "derivedUnsignedReveal.json",
    JSON.stringify(revealDocument, replacerMap, 2),
  );

  const groupIndexes = {
    mandatoryIndexes,
    selectiveIndexes,
  };
  await writeFile(
    baseDir + "derivedGroupIndexes.json",
    JSON.stringify(groupIndexes, replacerMap),
  );

  // **SerializeDerived-SHoC**
  // leafIndexes: positions of the disclosed statements among the
  // non-mandatory statements, i.e., the tree leaves.
  const leafIndexes = selectiveIndexes;
  const nonMandatoryStatements = [...nonMandatory.values()];
  if (nonMandatoryStatements.length !== treeSize) {
    throw new Error(`${nonMandatoryStatements.length} non-mandatory statements but treeSize is ${treeSize}`);
  }
  // Derive all salts from the seed and recompute every leaf hash.
  const salts = deriveSalts(saltSeed, treeSize);
  const leafHashes = nonMandatoryStatements.map((statement, j) => leafHash(salts[j], statement));
  // Holder sanity check, not a spec step: the recomputed root matches the
  // signed one, so the derived proof will verify.
  if (bytesToHex(mth(leafHashes)) !== bytesToHex(merkleRoot)) {
    throw new Error('Recomputed Merkle root does not match the base proof');
  }
  const subtreeProof = createSubtreeProof(treeSize, leafIndexes, leafHashes);
  const filteredSalts = leafIndexes.map((j) => salts[j]);

  // For readability: each subtree proof value with the tree node it is the
  // root of (N_a_b covers leaves a to b - 1, Leafj is leaf j).
  const nodeNames = subtreeProofNames(treeSize, leafIndexes);
  await writeFile(
    baseDir + "derivedSubtreeProof.json",
    JSON.stringify({
      treeSize,
      leafIndexes,
      subtreeProof: subtreeProof.map((value, i) => ({ node: nodeNames[i], value: bytesToHex(value) })),
    }, null, 2),
  );

  const disclosureData = {
    signature: bytesToHex(signature),
    treeSize,
    leafIndexes,
    filteredSalts: filteredSalts.map((s) => bytesToHex(s)),
    subtreeProof: subtreeProof.map((h) => bytesToHex(h)),
    labelMap: verifierLabelMap,
    mandatoryIndexes,
  };
  await writeFile(
    baseDir + "derivedDisclosureData.json",
    JSON.stringify(disclosureData, replacerMap, 2),
  );

  // Components: signature, treeSize, leafIndexes, filteredSalts,
  // subtreeProof, compressedLabelMap, mandatoryIndexes, behind the header
  // bytes 0xd9, 0x5d, 0x13.
  const derivedProofValueString = serializeDerivedProofValue({
    signature, treeSize, leafIndexes, filteredSalts, subtreeProof,
    labelMap: verifierLabelMap, mandatoryIndexes,
  });
  console.log(
    `Length of derivedProofValue is ${derivedProofValueString.length} characters`,
  );
  // Initialize newProof to a shallow copy of proof, replace its proofValue
  // and set it as the proof of the reveal document.
  const newProof = Object.assign({}, proof);
  newProof.proofValue = derivedProofValueString;
  revealDocument.proof = newProof;
  await writeFile(
    baseDir + "derivedRevealDocument.json",
    JSON.stringify(revealDocument, null, 2),
  );
}
