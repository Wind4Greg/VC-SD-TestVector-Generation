/*
    Walking through the steps for verifying a SHoC base proof. This is a
    holder-side check (the spec defines no base proof verification): the
    holder rebuilds the Merkle root from the salt seed and the non-mandatory
    statements, checks it against the root in the base proof, and checks the
    issuer's signature over proofHash || mandatoryHash || uint64be(treeSize)
    || merkleRoot.
*/
import { repoPath } from '../lib/paths.js';
import { parseBaseProofValue } from './proofValue.js';
import { deriveSalts, uint64be } from './salts.js';
import { leafHash, mth } from './merkle.js';
import { readFile } from "fs/promises";
import { klona } from "klona";
import {
  createHmac,
  canonicalizeAndGroup,
} from "@digitalbazaar/di-sd-primitives";
import { createShuffledIdLabelMapFunction } from '../lib/labelMaps.js';
import jsonld from "jsonld";
import { sha256 } from "@noble/hashes/sha256";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded } from "@noble/post-quantum/falcon.js";
import { localLoader } from "../lib/documentLoader.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
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
  console.log(`SD Base Verification starting for ${test.suiteName}`);
  const baseDir = test.baseDir;

  // Read base signed document from a file
  const document = JSON.parse(
    await readFile(baseDir + "addSignedSDBase.json"),
  );

  const options = { documentLoader: localLoader };

  // parseBaseProofValue:
  const proof = document.proof;
  delete document.proof; // IMPORTANT: all work uses document without proof
  const { signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers } =
    parseBaseProofValue(proof.proofValue);

  // Canonicalize with the shuffled label map and split into mandatory and
  // non-mandatory statements.
  const hmac = await createHmac({ key: hmacKey });
  const labelMapFactoryFunction = createShuffledIdLabelMapFunction({ hmac });
  const groups = {
    mandatory: mandatoryPointers,
  };
  const stuff = await canonicalizeAndGroup({
    document,
    labelMapFactoryFunction,
    groups,
    options,
  });
  const mandatoryMatch = stuff.groups.mandatory.matching;
  const nonMandatory = [...stuff.groups.mandatory.nonMatching.values()];

  // canonize proof configuration and hash it
  const proofConfig = klona(proof);
  proofConfig["@context"] = document["@context"];
  delete proofConfig.proofValue; // Don't forget to remove this
  const proofCanon = await jsonld.canonize(proofConfig);
  const proofHash = sha256(proofCanon);
  console.log(`proofHash: ${bytesToHex(proofHash)}`);

  const mandatoryCanon = [...mandatoryMatch.values()].join("");
  const mandatoryHash = sha256(mandatoryCanon);
  console.log(`mandatory hash: ${bytesToHex(mandatoryHash)}`);

  // Rebuild the Merkle root from the salt seed and the statements
  const treeSizeVerified = nonMandatory.length === treeSize;
  console.log(`treeSize ${treeSize} matches the ${nonMandatory.length} non-mandatory statements: ${treeSizeVerified}`);
  const salts = deriveSalts(saltSeed, nonMandatory.length);
  const leafHashes = nonMandatory.map((statement, j) => leafHash(salts[j], statement));
  const rootVerified = bytesToHex(mth(leafHashes)) === bytesToHex(merkleRoot);
  console.log(`Merkle root verified: ${rootVerified}`);

  // Check the signature
  const toVerify = concatBytes(
    proofHash,
    mandatoryHash,
    uint64be(treeSize),
    merkleRoot,
  );

  // Get issuer public key
  const encodedPbk = proof.verificationMethod
    .split("did:key:")[1]
    .split("#")[0];
  let pbk = base64url.decode(encodedPbk);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  console.log(`Public Key hex: Length: ${pbk.length}`);
  const signatureVerified = test.sigAlg.verify(signature, toVerify, pbk);
  console.log(`Signature verified: ${signatureVerified}`);

  const baseVerified = treeSizeVerified && rootVerified && signatureVerified;
  console.log(`Base proof verified: ${baseVerified}`);
}
