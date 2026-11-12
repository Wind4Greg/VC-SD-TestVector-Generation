/*
    Check the spec-based Merkle algorithms in shoc/merkle.js.

    Usage:
      node tools/merkleCheck.js [--simple-merkle <dir>]

    1. Equivalence with the SimpleMerkle reference implementation
       (https://github.com/Wind4Greg/SimpleMerkle): same Merkle root, same
       subtree proof values and node names in the same order, and each
       implementation verifies the other's proofs. Every subset of disclosed
       leaves for small trees, random subsets for larger ones. SimpleMerkle is
       loaded from a local checkout (default: ../SelectiveDisclosure/SimpleMerkle
       next to this repo, with its dependencies installed); if it isn't found
       this part is skipped.
    2. Tree sizes 0 and 1, which SimpleMerkle doesn't handle.
    3. Examples from the SimpleMerkle README and the spec text.
    4. The invariants stated in CreateSubtreeProof.
    5. Malformed and tampered proofs must fail.
    6. VerifySubtreeProof is sparse: verifying against a tree of 2^24 leaves
       takes milliseconds.

    Exits non-zero if any check fails.
*/
import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseArgs } from 'node:util'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, concatBytes } from '@noble/hashes/utils'
import { repoRoot } from '../lib/paths.js'
import {
  computeTreeShape, createSubtreeProof, expectedProofLength, leafHash, mth,
  subtreeProofNames, verifySubtreeProof
} from '../shoc/merkle.js'

const { values } = parseArgs({
  options: { 'simple-merkle': { type: 'string' } }
})
const simpleMerkleDir = resolve(values['simple-merkle'] ??
  join(repoRoot, '..', 'SelectiveDisclosure', 'SimpleMerkle'))

let passed = 0
let failed = 0
function check (condition, description) {
  if (condition) {
    passed++
  } else {
    failed++
    console.log(`FAIL: ${description}`)
  }
}
function throws (fn) {
  try { fn() } catch { return true }
  return false
}
const hex = arrays => arrays.map(bytesToHex)
const sameBytes = (a, b) => bytesToHex(a) === bytesToHex(b)
const sameList = (a, b) => JSON.stringify(hex(a)) === JSON.stringify(hex(b))

// Test data: statement j is "L<j>", salt j is the first 16 bytes of
// sha256("salt<j>"). SimpleMerkle takes the raw leaf data salt || statement.
const te = new TextEncoder()
function makeLeaves (n) {
  const salts = []
  const statements = []
  for (let j = 0; j < n; j++) {
    salts.push(sha256(te.encode(`salt${j}`)).slice(0, 16))
    statements.push(`L${j}`)
  }
  return {
    statements,
    salts,
    rawData: statements.map((s, j) => concatBytes(salts[j], te.encode(s))),
    leafHashes: statements.map((s, j) => leafHash(salts[j], s))
  }
}

// Deterministic pseudo-random subsets (mulberry32) so failures reproduce.
function rng (seed) {
  return () => {
    seed |= 0; seed = seed + 0x6D2B79F5 | 0
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed)
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t
    return ((t ^ t >>> 14) >>> 0) / 4294967296
  }
}
const random = rng(20261112)
function randomSubset (n) {
  const p = random()
  return [...Array(n).keys()].filter(() => random() < p)
}

// The proof element names are "N_a_b" or "Leafj"; return their leaf ranges.
function nameToRange (name) {
  if (name.startsWith('Leaf')) {
    const j = parseInt(name.slice(4))
    return [j, j + 1]
  }
  const [, a, b] = name.split('_').map(Number)
  return [a, b]
}

// Spec-side checks for one (treeSize, leafIndexes) case.
function checkCase (n, selected, leaves) {
  const label = `n=${n} selected=[${selected}]`
  const proof = createSubtreeProof(n, selected, leaves.leafHashes)
  const names = subtreeProofNames(n, selected)
  const root = mth(leaves.leafHashes)
  const disclosed = selected.map(j => leaves.leafHashes[j])
  check(sameBytes(verifySubtreeProof(n, selected, disclosed, proof), root),
    `${label}: verifySubtreeProof reconstructs the root`)
  check(expectedProofLength(n, selected) === proof.length,
    `${label}: expectedProofLength matches proof length`)
  check(names.length === proof.length, `${label}: one name per proof value`)
  // Invariants from CreateSubtreeProof
  check(proof.length <= n - selected.length,
    `${label}: proof length <= treeSize - disclosed count`)
  const covered = names.flatMap(name => {
    const [a, b] = nameToRange(name)
    return [...Array(b - a).keys()].map(i => a + i)
  })
  const undisclosed = [...Array(n).keys()].filter(j => !selected.includes(j))
  check(JSON.stringify(covered) === JSON.stringify(undisclosed),
    `${label}: proof subtrees are disjoint and cover exactly the undisclosed leaves`)
  check(names.every((name, i) => sameBytes(proof[i], mth(leaves.leafHashes.slice(...nameToRange(name))))),
    `${label}: each proof value is the MTH of its named subtree`)
  return { proof, names, root }
}

// 1. Equivalence with SimpleMerkle, plus spec-side checks for every case
const cases = []
for (let n = 2; n <= 12; n++) {
  for (let mask = 0; mask < (1 << n); mask++) {
    cases.push([n, [...Array(n).keys()].filter(j => mask & (1 << j))])
  }
}
for (let n = 13; n <= 100; n++) {
  cases.push([n, []], [n, [...Array(n).keys()]])
  for (let i = 0; i < 20; i++) cases.push([n, randomSubset(n)])
}
for (const n of [127, 128, 129, 255, 256, 257, 1000]) {
  for (let i = 0; i < 5; i++) cases.push([n, randomSubset(n)])
}

let simpleMerkle = null
if (existsSync(join(simpleMerkleDir, 'merkleMultiProof.js'))) {
  simpleMerkle = await import(pathToFileURL(join(simpleMerkleDir, 'merkleMultiProof.js')).href)
} else {
  console.log(`SimpleMerkle not found at ${simpleMerkleDir}: skipping the equivalence checks.`)
}

const leavesCache = new Map()
const leavesFor = n => {
  if (!leavesCache.has(n)) leavesCache.set(n, makeLeaves(n))
  return leavesCache.get(n)
}
let compared = 0
for (const [n, selected] of cases) {
  const leaves = leavesFor(n)
  const { proof, names, root } = checkCase(n, selected, leaves)
  if (simpleMerkle) {
    const label = `n=${n} selected=[${selected}]`
    const tree = new simpleMerkle.MerkleTree(leaves.rawData)
    check(sameBytes(tree.mth, root), `${label}: same Merkle root as SimpleMerkle`)
    check(sameList(tree.inclusionMultiProofValues(selected), proof),
      `${label}: same subtree proof values as SimpleMerkle`)
    check(JSON.stringify(tree.inclusionMultiProof(selected)) === JSON.stringify(names),
      `${label}: same subtree proof node names as SimpleMerkle`)
    const rawSelected = selected.map(j => leaves.rawData[j])
    check(sameBytes(simpleMerkle.verifyMultiProof(n, selected, rawSelected, proof), root),
      `${label}: SimpleMerkle verifies the spec implementation's proof`)
    compared++
  }
}
console.log(`Checked ${cases.length} (treeSize, leafIndexes) cases` +
  (simpleMerkle ? `, ${compared} compared against SimpleMerkle.` : '.'))

// 2. Tree sizes 0 and 1
const emptyHash = sha256(new Uint8Array(0))
check(sameBytes(mth([]), emptyHash), 'n=0: MTH is H()')
check(createSubtreeProof(0, [], []).length === 0, 'n=0: subtree proof is empty')
check(sameBytes(verifySubtreeProof(0, [], [], []), emptyHash), 'n=0: verify gives H()')
check(throws(() => verifySubtreeProof(0, [], [], [emptyHash])), 'n=0: non-empty proof rejected')
const one = makeLeaves(1)
check(sameBytes(mth(one.leafHashes), one.leafHashes[0]), 'n=1: MTH is the leaf hash itself')
checkCase(1, [], one)
checkCase(1, [0], one)
check(sameList(createSubtreeProof(1, [], one.leafHashes), one.leafHashes), 'n=1, none disclosed: proof is [leaf hash]')
check(createSubtreeProof(1, [0], one.leafHashes).length === 0, 'n=1, disclosed: proof is empty')

// 3. Examples from the SimpleMerkle README and the spec
const sameNames = (n, selected, expected) => check(
  JSON.stringify(subtreeProofNames(n, selected)) === JSON.stringify(expected),
  `n=${n} selected=[${selected}]: proof names ${expected.join(', ')}`)
sameNames(20, [0, 1, 7], ['N_2_4', 'N_4_6', 'Leaf6', 'N_8_16', 'N_16_20'])
sameNames(20, [6, 19], ['N_0_4', 'N_4_6', 'Leaf7', 'N_8_16', 'N_16_18', 'Leaf18'])
sameNames(20, [8, 9], ['N_0_8', 'N_10_12', 'N_12_16', 'N_16_20'])
const shape20 = computeTreeShape(20)
check(shape20.name === 'N_0_20' && shape20.left.name === 'N_0_16' && shape20.right.name === 'N_16_20',
  'n=20: root N_0_20 splits into N_0_16 and N_16_20')
// Spec: N = 15 with disclosures only in the left half emits a 7-leaf subtree.
check(subtreeProofNames(15, [2]).includes('N_8_15'), 'n=15, left disclosure only: N_8_15 (7 leaves) emitted')
// Spec: the leaves decompose into perfect subtrees whose sizes are the set
// bits of treeSize, left to right (N = 21 gives 16 + 4 + 1).
function decomposition (shape) {
  const size = shape.end - shape.start
  if ((size & (size - 1)) === 0) return [size]
  return [shape.left.end - shape.left.start, ...decomposition(shape.right)]
}
const setBits = n => [...n.toString(2)].map((bit, i, all) => bit === '1' ? 2 ** (all.length - 1 - i) : 0).filter(Boolean)
check(JSON.stringify(decomposition(computeTreeShape(21))) === '[16,4,1]', 'n=21: decomposes into 16 + 4 + 1')
let decompositionOk = true
for (let n = 1; n <= 2000; n++) {
  if (JSON.stringify(decomposition(computeTreeShape(n))) !== JSON.stringify(setBits(n))) decompositionOk = false
}
check(decompositionOk, 'n=1..2000: perfect subtree sizes are the set bits of treeSize')

// 5. Malformed and tampered proofs
{
  const n = 20
  const selected = [0, 1, 7, 12]
  const leaves = makeLeaves(n)
  const proof = createSubtreeProof(n, selected, leaves.leafHashes)
  const root = mth(leaves.leafHashes)
  const disclosed = selected.map(j => leaves.leafHashes[j])
  const flipped = bytes => { const copy = bytes.slice(); copy[0] ^= 1; return copy }

  const badLeaves = disclosed.slice()
  badLeaves[2] = leafHash(leaves.salts[7], 'tampered statement')
  check(!sameBytes(verifySubtreeProof(n, selected, badLeaves, proof), root), 'tampered disclosed leaf gives a different root')
  const badSalt = disclosed.slice()
  badSalt[0] = leafHash(leaves.salts[1], leaves.statements[0])
  check(!sameBytes(verifySubtreeProof(n, selected, badSalt, proof), root), 'wrong salt gives a different root')
  for (let i = 0; i < proof.length; i++) {
    const badProof = proof.slice()
    badProof[i] = flipped(proof[i])
    check(!sameBytes(verifySubtreeProof(n, selected, disclosed, badProof), root), `tampered proof value ${i} gives a different root`)
  }
  check(!sameBytes(verifySubtreeProof(n, selected, disclosed, [...proof.slice(1), proof[0]]), root), 'reordered proof gives a different root')
  check(throws(() => verifySubtreeProof(n, selected, disclosed, [...proof, proof[0]])), 'extra proof value rejected')
  check(throws(() => verifySubtreeProof(n, selected, disclosed, proof.slice(1))), 'missing proof value rejected')
  check(throws(() => verifySubtreeProof(n, [0, 7, 1, 12], disclosed, proof)), 'unsorted leafIndexes rejected')
  check(throws(() => verifySubtreeProof(n, [0, 1, 1, 12], disclosed, proof)), 'duplicate leafIndexes rejected')
  check(throws(() => verifySubtreeProof(n, [0, 1, 7, 20], disclosed, proof)), 'out of range leafIndexes rejected')
  check(throws(() => verifySubtreeProof(n, [-1, 1, 7, 12], disclosed, proof)), 'negative leafIndexes rejected')
  check(throws(() => verifySubtreeProof(n, selected, disclosed.slice(1), proof)), 'leaf hash count mismatch rejected')
  // The root alone does not bind treeSize: every tree of 17 to 32 leaves
  // splits at the root into [0, 16) and a right subtree, which here is
  // undisclosed and so a single proof value whatever its size. This is why
  // the spec signs uint64be(treeSize) along with the root (SerializeBase-SHoC)
  // and notes in VerifySubtreeProof that treeSize must be covered by the base
  // signature.
  const sameRootSizes = []
  for (let size = 13; size <= 40; size++) {
    try {
      if (sameBytes(verifySubtreeProof(size, selected, disclosed, proof), root)) sameRootSizes.push(size)
    } catch { /* rejected */ }
  }
  check(JSON.stringify(sameRootSizes) === JSON.stringify([...Array(16).keys()].map(i => i + 17)),
    `treeSize 17..32 all reconstruct the n=20 root, so treeSize must be signed (got ${sameRootSizes})`)
  check(!sameBytes(verifySubtreeProof(n, [0, 1, 8, 12], disclosed, proof), root) ||
    throws(() => verifySubtreeProof(n, [0, 1, 8, 12], disclosed, proof)), 'wrong leaf position does not reconstruct the root')
}

// 6. Sparse verification: 2^24 leaves (the spec's suggested policy bound),
// three disclosed. The proof values are dummies; only the cost is checked.
{
  const n = 2 ** 24
  const selected = [5, 1000000, n - 1]
  const proofLength = expectedProofLength(n, selected)
  const start = performance.now()
  verifySubtreeProof(n, selected, selected.map(() => emptyHash), Array(proofLength).fill(emptyHash))
  const ms = performance.now() - start
  check(ms < 1000, `sparse verification of a 2^24 leaf tree took ${ms.toFixed(1)} ms`)
  console.log(`Sparse check: 2^24 leaves, 3 disclosed, proof length ${proofLength}, verified in ${ms.toFixed(1)} ms.`)
}

console.log(`\n${passed} checks passed, ${failed} failed.`)
if (failed > 0) process.exit(1)
