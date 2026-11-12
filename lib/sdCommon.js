/*
# Refactoring Selective Disclosure Proposal

Three general approaches: (1) Signed Individual Claims (SIC), (2) Salted  Hash of Claims (SHoC), and  (3) Multi Claim Signatures (MCS). Examples: ECDSA-SD, Quantum-Resistant-SD, and BBS respectively.

Highest Level Approach Specific Procedures:

1. Create Base Proof
2. Add Derived Proof
3. Verify Derived Proof

These depend on whether SIC, SHoC or MCS.

## Proposal Across Approaches

1. **Create Base Proof**
   1. *Base Proof Configuration*: return canonicalized proof config. ***General***
   2. *Base Proof Transformation*: **General** canonicalizes and returns object with 
   separated lists of mandatory and non-mandatory claims. Does shuffling. Only difference 
   is choice of label map function. Can use the same for BBS and Quantum-Resistant-SD. The 
   kind used in ECDSA-SD produces linkable artifacts and  can't be used with BBS.
   3. *Bash Proof Hashing*:  computes *proofHash* and *mandatoryHash* in all cases. In SHoC case adds *salts* and *saltedHashes* as well. Can make ***general***  or partial reuse.
   4. *Base Proof Serialization*: This is where signatures are actually computed. Would need a different variant for SIC, SHoC, and BBS. For SIC and SHoC the signature algorithms.
2. **Add Derived Proof** (proposed)
   1. *Parse Base Proof* (specific to approaches)
   2. New ***general*** *Create Disclosure Data*: returns  {labelMap, mandatoryIndexes, selectiveIndexes, revealDocument}
   3. New *Serialize Derived Proof*
      1. In SIC case creates filtered signatures from selectiveIndexes
      2. In BBS case computes BBS proof
      3. In all cases approach specific serialization
3. **Verify Derived Proof** (proposed)
   1. *Parse Derived Proof* -- approach specific returns all the encoded parameters
   2. New *Create Verify Data* ***general*** returns {proofHash, nonMandatory, and mandatoryHash}
   3. New *Derived Proof Verification* approach specific cryptographic verification procedures.

*/
import { randomBytes } from "crypto";
import { klona } from "klona";
import jsonld from "jsonld"; // For RDFC
import { localLoader } from "./documentLoader.js";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { base64url } from 'multiformats/bases/base64'
import { canonicalize, createLabelMapFunction, labelReplacementCanonicalizeJsonLd } from '@digitalbazaar/di-sd-primitives'
import { createHmac, createHmacIdLabelMapFunction, canonicalizeAndGroup } from '@digitalbazaar/di-sd-primitives'
import { selectJsonLd, stripBlankNodePrefixes } from '@digitalbazaar/di-sd-primitives'
import { createShuffledIdLabelMapFunction } from './labelMaps.js'

jsonld.documentLoader = localLoader; // Local loader for JSON-LD
const options = { documentLoader: localLoader };

/**
 * 
 * @param {object} proofOptions - proofOptions should not include the proofValue field
 * @param {object} document - used only to get @context information
 * @param {string} hash - what hash to feed to the RDF canonicalization algorithm
 * @returns canonicalized document as a multi-line string.
 */
export async function proofConfigCanon(proofOptions, document, hash = "sha256") {
  const copyProofOptions = klona(proofOptions);
  copyProofOptions["@context"] = document["@context"];
  let proofCanon;
  let canonizeOptions = {
    algorithm: "RDFC-1.0",
    messageDigestAlgorithm: hash,
    maxWorkFactor: 1,
    maxDeepIterations: -1,
    signal: null,
  };
  proofCanon = await jsonld.canonize(copyProofOptions, { canonizeOptions });
  return proofCanon;
}

/**
 * Performs the selective disclosure transformation which canonicalizes the document
 * and separates into mandatory and non-mandatory claims (in NQuad format).
 * @param {object} document - unsigned document
 * @param {object} mandatoryPointers - array of mandatory pointers
 * @param {Uint8Array} hmacKey - HMAC key
 * @param {string} hash - Hash name
 * @param {boolean} ecdsaLabelMap - Use legacy  ECDSA-SD style label map.
 * @returns 
 */
export async function transformSD(document, mandatoryPointers, hmacKey, ecdsaLabelMap = false) {
  const hmacFunc = await createHmac({ key: hmacKey });
  let labelMapFactoryFunction;
  if (ecdsaLabelMap) {
    labelMapFactoryFunction = createHmacIdLabelMapFunction({hmac: hmacFunc});
  } else {
    labelMapFactoryFunction = createShuffledIdLabelMapFunction({ hmac: hmacFunc })
  }

  const groups = { mandatory: mandatoryPointers };
  const stuff = await canonicalizeAndGroup({document, labelMapFactoryFunction, groups,  options});
  const mandatory = stuff.groups.mandatory.matching;
  const nonMandatory = stuff.groups.mandatory.nonMatching;
  return {mandatory, nonMandatory};
}

/**
 * Produces hashes of proof configuration and mandatory claims.
 * @param {array} mandatoryQuads - array of mandatoryQuads
 * @param {string} canonicalProofConfig - canonicalized proof configuration
 * @param {string} hash - name of hash to use
 * @returns object - {proofHash, mandatoryHash}
 */
export function hashingSD(mandatoryQuads, canonicalProofConfig, hash = "sha256") {
  const encoder = new TextEncoder(); // Use encoder to convert to Uint8Array
  let hashFunc;
  switch (hash) {
    case "sha256":
      hashFunc = sha256;
      break;
    case "sha384":
      hashFunc = sha384;
      break;
    case "sha512":
      hashFunc = sha512;
      break;
    default:
      throw new Error("Unsupported hash function");
  }
  const mandatoryHash = hashFunc([...mandatoryQuads.values()].join(""));
  const proofHash = hashFunc(encoder.encode(canonicalProofConfig));
  return {proofHash, mandatoryHash};
}

/**
 * Produces list of salts and salted hashes for salted hash based selective
 * disclosure.
 * @param {array} nonMandatoryQuads - non mandatory NQuads
 * @param {string} hashName -
 * @returns {salts, saltedHashes}
 */
export function saltedHashingSD(nonMandatoryQuads, hashName="sha256") {
  const encoder = new TextEncoder(); // Use encoder to convert to Uint8Array
  let hashFunc;
  let saltSize;
  switch (hashName) {
    case "sha256":
      hashFunc = sha256;
      saltSize = 16; //in bytes, half the size of the hash value
      break;
    case "sha384":
      hashFunc = sha384;
      saltSize = 24;
      break;
    case "sha512":
      hashFunc = sha512;
      saltSize = 32;
      break;
    default:
      throw new Error("Unsupported hash function");
  }
  let salts = [];
  let saltedHashes = [];
  nonMandatoryQuads.forEach(function (value, key) {
    let salt = new Uint8Array(randomBytes(saltSize)); // **WARNING** randomBytes returns a Buffer we need Uint8Array!!!
    salts.push(salt);
    let saltedHash = hashFunc(concatBytes(salt, encoder.encode(value)));
    saltedHashes.push(saltedHash);
  });
  return {salts, saltedHashes};
}

/**
 * Creates all the data needed for the selectively disclosed document and
 * to generate the derived proof. Does not compute the derived proof.
 * @param {Object} document - document without proof
 * @param {array} mandatoryPointers - mandatory pointers
 * @param {array} selectivePointers - selective pointers
 * @param {Uint8Array} hmacKey - HMAC key bytes
 * @param {boolean} ecdsaLabelMap - use legacy ECDSA-SD label map
 * @returns {revealDocument, mandatoryIndexes, selectiveIndexes, 
 * verifierLabelMap, mandatory, nonMandatory}
 */
export async function createDisclosureData(document, mandatoryPointers, selectivePointers, hmacKey,  
  ecdsaLabelMap = false) {
  const combinedPointers = mandatoryPointers.concat(selectivePointers);
  // **Create unsigned selectively disclosed document**, i.e., the reveal document
  const revealDocument = selectJsonLd({ document, pointers: combinedPointers });

  // **Create indexes for
  const hmacFunc = await createHmac({ key: hmacKey });
  let labelMapFactoryFunction;
  if (ecdsaLabelMap) {
    labelMapFactoryFunction = createHmacIdLabelMapFunction({hmac: hmacFunc});
  } else {
    labelMapFactoryFunction = createShuffledIdLabelMapFunction({ hmac: hmacFunc })
  }
  const groups = {mandatory: mandatoryPointers, selective: selectivePointers,
    combined: combinedPointers};
  const stuff = await canonicalizeAndGroup({document, labelMapFactoryFunction, groups, options});
  const combinedMatch = stuff.groups.combined.matching;
  const mandatoryMatch = stuff.groups.mandatory.matching;
  const mandatoryNonMatch = stuff.groups.mandatory.nonMatching; // For reverse engineering
  const selectiveMatch = stuff.groups.selective.matching;
  const combinedIndexes = [...combinedMatch.keys()];
  const nonMandatoryIndexes = [...mandatoryNonMatch.keys()];
  const selectiveIndexes = [...selectiveMatch.keys()];
  /*
    My simplification. Compute the "adjusted mandatory indexes" relative to their
    positions in the combined statement list, i.e., find at what position a mandatory
    statement occurs in the list of combined statements.
  */
  const adjMandatoryIndexes = [];
  mandatoryMatch.forEach((value, index) => {
    adjMandatoryIndexes.push(combinedIndexes.indexOf(index));
  });
  /* Determine which signatures match a selectively disclosed statement.
  First determine the "adjusted signature indexes", i.e., relative to their
  place in the list of statements with signatures. These correspond to the
  non-mandatory statements.
  */
  const adjSelectiveIndexes = [];
  selectiveMatch.forEach((value, index) => {
    const adjIndex = nonMandatoryIndexes.indexOf(index);
    if (adjIndex !== -1) {
      adjSelectiveIndexes.push(adjIndex);
    }
  });

  // **Create the verifier label map**
  /*
  Run the RDF Dataset Canonicalization Algorithm [RDF-CANON] on the joined combinedGroup.deskolemizedNQuads,
  passing any custom options, and get the canonical bnode identifier map, canonicalIdMap. Note: This map
  includes the canonical blank node identifiers that a verifier will produce when they canonicalize the
  reveal document.
  */
  const deskolemizedNQuads = stuff.groups.combined.deskolemizedNQuads;
  let canonicalIdMap = new Map();
  // The goal of the below is to get the canonicalIdMap and not the canonical document
  await canonicalize(deskolemizedNQuads.join(""), {
      ...options,
      inputFormat: "application/n-quads",
      canonicalIdMap,
  });
  // console.log(JSON.stringify(canonicalIdMap, replacerMap, 2))
  canonicalIdMap = stripBlankNodePrefixes(canonicalIdMap);
  // console.log(JSON.stringify(canonicalIdMap, replacerMap, 2))
  /* Initialize verifierLabelMap to an empty map. This map will map the canonical blank node identifiers
   the verifier will produce when they canonicalize the revealed document to the blank node identifiers
    that were originally signed in the base proof. (step 13)
  */
  const verifierLabelMap = new Map();
  /* For each key (inputLabel) and value (verifierLabel) in `canonicalIdMap:
    Add an entry to verifierLabelMap using verifierLabel as the key and the value associated with inputLabel
    as a key in labelMap as the value.
  */
  const labelMap = stuff.labelMap;
  // console.log("Label Map  from createDisclosureData:");
  // console.log(labelMap);
  // console.log("Canonical ID  map from createDisclosureData:");
  // console.log(canonicalIdMap);
  canonicalIdMap.forEach(function (value, key) {verifierLabelMap.set(value, labelMap.get(key));});
  // console.log(verifierLabelMap);
  return {revealDocument, mandatoryIndexes: adjMandatoryIndexes, 
    selectiveIndexes: adjSelectiveIndexes, verifierLabelMap, mandatory:stuff.groups.mandatory.matching,
    nonMandatory: stuff.groups.mandatory.nonMatching};
}

// *Create Verify Data* ***general*** returns {proofHash, nonMandatory, and mandatoryHash}

export async function createVerifyData(sdDocument, labelMapCompressed, mandatoryIndexes, ecdsaLabelMap = false) {
  // *Create Verify Data*
  
  const proof = sdDocument.proof
  const proofConfig = klona(sdDocument.proof)
  delete proofConfig.proofValue
  proofConfig['@context'] = sdDocument['@context']
  delete sdDocument.proof // **IMPORTANT** from now on we work with the document without proof!!!!!!!
  const proofCanon = await jsonld.canonize(proofConfig)
  const proofHash = sha256(proofCanon) // @noble/hash will convert string to bytes via UTF-8

  // 3.4.6 decompressLabelMap
  const labelMap = new Map()
  labelMapCompressed.forEach(function (v, k) {
    const key = 'c14n' + k;
    if(ecdsaLabelMap) {
      const value = base64url.encode(v);
      labelMap.set(key, value);
    } else {
      const value = 'b' + v
      labelMap.set(key, value)
    }

  })

  const labelMapFactoryFunction = await createLabelMapFunction({ labelMap });

  /* Initialize nquads to the result of calling the "labelReplacementCanonicalize" algorithm, passing
    document, labelMapFactoryFunction, and any custom JSON-LD API options. Note: This step transforms
    the document into an array of canonical N-Quads with pseudorandom blank node identifiers based on
    labelMap.
  */
  // console.log(labelMap);
  // console.log(labelMapFactoryFunction);
  const nquads = await labelReplacementCanonicalizeJsonLd({document: sdDocument, labelMapFactoryFunction, options: { documentLoader: localLoader }});
  // Separate into mandatory and non-mandatory
  const mandatory = []
  const nonMandatory = []
  nquads.forEach(function (value, index) {
    if (mandatoryIndexes.includes(index)) {
      mandatory.push(value)
    } else {
      nonMandatory.push(value)
    }
  })
  // **CAUTION** JavaScript join() without argument uses ',' comma!!!
  const mandatoryHash = sha256(mandatory.join(''));
  return {proofHash, mandatoryHash, nonMandatory}
}
