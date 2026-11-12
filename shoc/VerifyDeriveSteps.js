/*
    Walking through the steps for verifying a derived SHoC selective
    disclosure proof, following VerifyDerived-SHoC in VC-Data-Integrity.

    The verifier hashes each disclosed statement with its salt from the
    derived proof, reconstructs the Merkle root from those leaf hashes and
    the subtree proof (VerifySubtreeProof), and checks the issuer's signature
    over proofHash || mandatoryHash || uint64be(treeSize) || root.

    Key initialization step: [3.4.9 createVerifyData](https://w3c.github.io/vc-di-ecdsa/#createverifydata)
*/
import { repoPath } from '../lib/paths.js';
import { parseDerivedProofValue } from './proofValue.js';
import { uint64be } from './salts.js';
import { expectedProofLength, leafHash, verifySubtreeProof } from './merkle.js';
import { createVerifyData } from '../lib/sdCommon.js';
import { readFile } from "fs/promises";
import jsonld from "jsonld";
import { localLoader } from "../lib/documentLoader.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded } from "@noble/post-quantum/falcon.js";
import { base64url } from "multiformats/bases/base64";

jsonld.documentLoader = localLoader; // Local loader for JSON-LD

const testCases = [
  {
    suiteName: "mldsa44-sd-2024",
    baseDir: repoPath('shoc/output/mldsa44-sd-2024/employ/'),
    sigAlg: ml_dsa44,
  },
  {
    suiteName: "slhdsa128-sd-2024",
    baseDir: repoPath('shoc/output/slhdsa128-sd-2024/employ/'),
    sigAlg: slh_dsa_sha2_128s,
  },
  {
    suiteName: "falcon512-sd-2024",
    baseDir: repoPath('shoc/output/falcon512-sd-2024/employ/'),
    sigAlg: falcon512padded,
  },
];

for (const test of testCases) {
  const baseDir = test.baseDir;

  // Read the derived (selectively disclosed) document
  const document = JSON.parse(
    await readFile(baseDir + "derivedRevealDocument.json"),
  );
  const proof = document.proof;

  //  **ParseDerived-SHoC**
  // Checks the header, the component types and lengths, that the leaf
  // indexes are ascending and within treeSize, and the treeSize policy bound.
  const { signature, treeSize, leafIndexes, salts, subtreeProof,
    compressedLabelMap, mandatoryIndexes } = parseDerivedProofValue(proof.proofValue);

  // get additional verify data
  const { proofHash, mandatoryHash, nonMandatory } =
    await createVerifyData(document, compressedLabelMap, mandatoryIndexes, false);

  // **VerifyDerived-SHoC**
  let verified = true;
  const fail = (message) => {
    console.log(`Check failed: ${message}`);
    verified = false;
  };
  if (salts.length !== leafIndexes.length) {
    fail(`${salts.length} salts for ${leafIndexes.length} disclosed leaves`);
  }
  if (subtreeProof.length !== expectedProofLength(treeSize, leafIndexes)) {
    fail(`subtree proof has ${subtreeProof.length} values, expected ${expectedProofLength(treeSize, leafIndexes)}`);
  }
  // Every non-mandatory statement in the presented document must be
  // accounted for by exactly one leaf index.
  if (nonMandatory.length !== leafIndexes.length) {
    fail(`${nonMandatory.length} non-mandatory statements for ${leafIndexes.length} disclosed leaves`);
  }

  // Positional pairing: statement i is hashed with salts[i]. leafIndexes[i]
  // is only its leaf position in the tree.
  let reconstructedRoot = null;
  if (verified) {
    const disclosedLeafHashes = nonMandatory.map((statement, i) => leafHash(salts[i], statement));
    try {
      reconstructedRoot = verifySubtreeProof(treeSize, leafIndexes, disclosedLeafHashes, subtreeProof);
      console.log(`Reconstructed Merkle root: ${bytesToHex(reconstructedRoot)}`);
    } catch (error) {
      fail(`VerifySubtreeProof: ${error.message}`);
    }
  }

  if (verified) {
    // Get public key
    const encodedPbk = proof.verificationMethod.split("did:key:")[1];
    let pbk = base64url.decode(encodedPbk);
    pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator

    const toVerify = concatBytes(
      proofHash,
      mandatoryHash,
      uint64be(treeSize),
      reconstructedRoot,
    );
    const signatureVerified = test.sigAlg.verify(signature, toVerify, pbk);
    console.log(`Base Signature verified: ${signatureVerified}`);
    verified &&= signatureVerified;
  }

  console.log(`${test.suiteName} Derived document verified: ${verified}`);
}
