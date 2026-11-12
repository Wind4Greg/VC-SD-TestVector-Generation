/*
    Check the SHoC salt derivation and proof value encoding.

    Usage:
      node tools/shocCheck.js

    1. deriveSalts (DeriveSaltsSD) matches an independent computation with
       Node's crypto HMAC, using the fixed test seed in input/SaltSeed.json,
       and prints the first salts as test values.
    2. Base (0xd9 0x5d 0x12) and derived (0xd9 0x5d 0x13) proof values round
       trip through serialize and parse.
    3. Malformed proof values are rejected by the parse functions.

    Exits non-zero if any check fails.
*/
import { createHmac } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { repoPath } from '../lib/paths.js'
import { serializeProofValue } from '../lib/proofValue.js'
import { createSubtreeProof, leafHash, mth } from '../shoc/merkle.js'
import {
  MAX_TREE_SIZE, parseBaseProofValue, parseDerivedProofValue,
  serializeBaseProofValue, serializeDerivedProofValue
} from '../shoc/proofValue.js'
import { deriveSalts, SALT_LENGTH, uint64be } from '../shoc/salts.js'

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
// Deep equality good enough for CBOR-decoded values: bytes, arrays, maps,
// strings and numbers.
function same (a, b) {
  if (a instanceof Uint8Array && b instanceof Uint8Array) return bytesToHex(a) === bytesToHex(b)
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((x, i) => same(x, b[i]))
  if (a instanceof Map && b instanceof Map) return a.size === b.size && [...a].every(([k, v]) => same(v, b.get(k)))
  return a === b
}

// 1. Salt derivation
const { saltSeedString } = JSON.parse(await readFile(repoPath('input/SaltSeed.json')))
const saltSeed = hexToBytes(saltSeedString)
check(saltSeed.length === 32, 'test salt seed is 32 bytes')

check(bytesToHex(uint64be(0)) === '0000000000000000', 'uint64be(0)')
check(bytesToHex(uint64be(258)) === '0000000000000102', 'uint64be(258)')
check(bytesToHex(uint64be(2 ** 32 + 1)) === '0000000100000001', 'uint64be(2^32 + 1) has no 32-bit overflow')

const count = 40
const salts = deriveSalts(saltSeed, count)
const independent = [...Array(count).keys()].map(i => {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(i))
  return createHmac('sha256', Buffer.from(saltSeed)).update(counter).digest().subarray(0, 16)
})
check(salts.length === count, `deriveSalts gives ${count} salts`)
check(salts.every(s => s.length === SALT_LENGTH), 'every salt is 16 bytes')
check(salts.every((s, i) => bytesToHex(s) === independent[i].toString('hex')),
  'deriveSalts matches node:crypto HMAC-SHA-256(saltSeed, uint64be(i))[0:16]')
check(deriveSalts(saltSeed, 0).length === 0, 'count 0 gives no salts')
check(same(deriveSalts(saltSeed, 5), salts.slice(0, 5)), 'salts[i] depends only on (saltSeed, i)')
check(deriveSalts(saltSeed.slice(0, 16), 1).length === 1, '16-byte seed accepted')
check(throws(() => deriveSalts(saltSeed.slice(0, 15), 1)), '15-byte seed rejected')
check(throws(() => deriveSalts(new Uint8Array(33), 1)), '33-byte seed rejected')
check(throws(() => deriveSalts(saltSeed, -1)), 'negative count rejected')

console.log('Test values, salt seed from input/SaltSeed.json:')
for (let i = 0; i < 3; i++) console.log(`  salts[${i}] = ${bytesToHex(salts[i])}`)

// Sample data for the proof values: 10 statements, leaves 1, 4, 5, 6 disclosed.
const treeSize = 10
const statements = [...Array(treeSize).keys()].map(j => `statement ${j}\n`)
const treeSalts = deriveSalts(saltSeed, treeSize)
const leafHashes = statements.map((s, j) => leafHash(treeSalts[j], s))
const merkleRoot = mth(leafHashes)
const leafIndexes = [1, 4, 5, 6]
const subtreeProof = createSubtreeProof(treeSize, leafIndexes, leafHashes)
const filteredSalts = leafIndexes.map(j => treeSalts[j])
const signature = sha256(new TextEncoder().encode('stand-in signature'))
const hmacKey = hexToBytes('00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF')
const mandatoryPointers = ['/issuer', '/credentialSubject/name']
const labelMap = new Map([['c14n0', 'b2'], ['c14n1', 'b0'], ['c14n2', 'b1']])
const compressedLabelMap = new Map([[0, 2], [1, 0], [2, 1]])
const mandatoryIndexes = [0, 2, 3]

// 2. Round trips
const base = { signature, hmacKey, saltSeed, treeSize, merkleRoot, mandatoryPointers }
const baseProof = serializeBaseProofValue(base)
const parsedBase = parseBaseProofValue(baseProof)
check(Object.keys(base).every(k => same(parsedBase[k], base[k])), 'base proof value round trips')

const derived = { signature, treeSize, leafIndexes, filteredSalts, subtreeProof, labelMap, mandatoryIndexes }
const derivedProof = serializeDerivedProofValue(derived)
const parsedDerived = parseDerivedProofValue(derivedProof)
check(same(parsedDerived.signature, signature) && parsedDerived.treeSize === treeSize &&
  same(parsedDerived.leafIndexes, leafIndexes) && same(parsedDerived.salts, filteredSalts) &&
  same(parsedDerived.subtreeProof, subtreeProof) &&
  same(parsedDerived.compressedLabelMap, compressedLabelMap) &&
  same(parsedDerived.mandatoryIndexes, mandatoryIndexes), 'derived proof value round trips')

const emptyBase = { ...base, treeSize: 0, merkleRoot: mth([]) }
check(parseBaseProofValue(serializeBaseProofValue(emptyBase)).treeSize === 0, 'empty tree base proof accepted')
const emptyDerived = { ...derived, treeSize: 0, leafIndexes: [], filteredSalts: [], subtreeProof: [] }
check(parseDerivedProofValue(serializeDerivedProofValue(emptyDerived)).treeSize === 0, 'empty tree derived proof accepted')

// 3. Malformed proof values
const baseArray = b => [b.signature, b.hmacKey, b.saltSeed, b.treeSize, b.merkleRoot, b.mandatoryPointers]
const badBase = (changes, description, header = 0x12) => check(
  throws(() => parseBaseProofValue(serializeProofValue(header, baseArray({ ...base, ...changes })))),
  `base: ${description} rejected`)
badBase({}, 'old 0x10 header', 0x10)
badBase({}, 'derived 0x13 header', 0x13)
check(throws(() => parseBaseProofValue(serializeProofValue(0x12, baseArray(base).slice(0, 5)))), 'base: 5 components rejected')
check(throws(() => parseBaseProofValue(baseProof.slice(1))), 'base: missing multibase prefix rejected')
badBase({ saltSeed: saltSeed.slice(0, 15) }, '15-byte saltSeed')
badBase({ saltSeed: new Uint8Array(33) }, '33-byte saltSeed')
badBase({ treeSize: -1 }, 'negative treeSize')
badBase({ treeSize: 1.5 }, 'non-integer treeSize')
badBase({ merkleRoot: merkleRoot.slice(0, 31) }, '31-byte merkleRoot')
badBase({ hmacKey: hmacKey.slice(0, 16) }, '16-byte hmacKey')
badBase({ mandatoryPointers: ['/issuer', 7] }, 'non-string mandatory pointer')
badBase({ signature: 'not bytes' }, 'non-byte signature')

const derivedArray = d => [d.signature, d.treeSize, d.leafIndexes, d.filteredSalts, d.subtreeProof,
  d.compressedLabelMap ?? compressedLabelMap, d.mandatoryIndexes]
const badDerived = (changes, description, header = 0x13, options) => check(
  throws(() => parseDerivedProofValue(serializeProofValue(header, derivedArray({ ...derived, ...changes })), options)),
  `derived: ${description} rejected`)
badDerived({}, 'old 0x11 header', 0x11)
badDerived({}, 'base 0x12 header', 0x12)
check(throws(() => parseDerivedProofValue(serializeProofValue(0x13, derivedArray(derived).slice(0, 6)))), 'derived: 6 components rejected')
badDerived({ treeSize: MAX_TREE_SIZE + 1 }, 'treeSize over the 2^24 policy bound')
badDerived({}, 'treeSize over a configured bound of 8', 0x13, { maxTreeSize: 8 })
badDerived({ leafIndexes: [1, 5, 4, 6] }, 'unsorted leafIndexes')
badDerived({ leafIndexes: [1, 4, 4, 6] }, 'duplicate leafIndexes')
badDerived({ leafIndexes: [1, 4, 5, 10] }, 'leafIndex equal to treeSize')
badDerived({ leafIndexes: [1, 4, 5] }, 'fewer leafIndexes than salts')
badDerived({ filteredSalts: [...filteredSalts.slice(0, 3), new Uint8Array(15)] }, '15-byte salt')
badDerived({ subtreeProof: [...subtreeProof.slice(1), new Uint8Array(31)] }, '31-byte subtree proof value')
badDerived({ compressedLabelMap: new Map([[0, new Uint8Array(32)]]) }, 'label map with a byte-array value (the SIC form)')
badDerived({ mandatoryIndexes: [0, 'two'] }, 'non-integer mandatory index')
check(parseDerivedProofValue(derivedProof, { maxTreeSize: 10 }).treeSize === 10, 'derived: treeSize equal to a configured bound accepted')

console.log(`\n${passed} checks passed, ${failed} failed.`)
if (failed > 0) process.exit(1)
