/*
    Walking through the steps for verifying a PQC-SD base proof.
*/
import { repoPath } from '../lib/paths.js';
import { parseBaseProofValue } from './proofValue.js';
import { mkdir, readFile } from "fs/promises";
import { klona } from "klona";
import {
  createHmac,
  canonicalizeAndGroup,
} from "@digitalbazaar/di-sd-primitives";
import { createShuffledIdLabelMapFunction } from '../lib/labelMaps.js'
import jsonld from "jsonld";
import { sha256 } from "@noble/hashes/sha256";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { falcon512padded } from "@noble/post-quantum/falcon.js";
import { localLoader } from "../lib/documentLoader.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils";
import { base64url } from "multiformats/bases/base64";

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

for (let test of testCases) {
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
  const { signature, hmacKey, salts, saltedHashes, mandatoryPointers } =
    parseBaseProofValue(proof.proofValue);

  // check we got the salts  and  saltedHashes
  // let saltedHashInfo = {
  //   saltsHex: salts.map((s) => bytesToHex(new Uint8Array(s))),
  //   saltedHashesHex: saltedHashes.map((sh) => bytesToHex(new Uint8Array(sh))),
  // };
  // console.log(JSON.stringify(saltedHashInfo, null, 2));
  // setup HMAC stuff
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
  const mandatoryNonMatch = stuff.groups.mandatory.nonMatching;

  // Check signature;
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

  const signData = concatBytes(
    proofHash,
    mandatoryHash,
    ...saltedHashes,
  );

  // Get issuer public key
  // console.log(proof.verificationMethod.split('did:key:'))
  const encodedPbk = proof.verificationMethod
    .split("did:key:")[1]
    .split("#")[0];
  let pbk = base64url.decode(encodedPbk);
  pbk = pbk.slice(2, pbk.length); // First two bytes are multi-format indicator
  console.log(`Public Key hex: Length: ${pbk.length}`);
  let verificationResult = test.sigAlg.verify(signature, sha256(signData), pbk);
  console.log(`Signature verified: ${verificationResult}`);

  const utf8encoder = new TextEncoder(); // To convert utf8 text to Uint8Array

  // Check each non-mandatory nquad salted hash
  const nonMandatory = [...mandatoryNonMatch.values()];
  let baseVerified = verificationResult;
  nonMandatory.forEach((value, index) => {
    let aSaltedHash = sha256(
      concatBytes(salts[index], utf8encoder.encode(value)),
    );
    verificationResult = isEqual(aSaltedHash, saltedHashes[index]);
    console.log(`Salted hash ${index} verified: ${verificationResult}`);
    baseVerified &&= verificationResult;
  });
  console.log(`Base proof verified: ${baseVerified}`);
}
