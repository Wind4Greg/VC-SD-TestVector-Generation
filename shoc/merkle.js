/*
    Merkle tree algorithms for the SHoC approach, written directly from the
    VC-Data-Integrity specification sections:

      Merkle Tree Hash (MTH)  https://w3c.github.io/vc-data-integrity/#MTH
      ComputeTreeShape        https://w3c.github.io/vc-data-integrity/#ComputeTreeShape
      CreateSubtreeProof      https://w3c.github.io/vc-data-integrity/#CreateSubtreeProof
      VerifySubtreeProof      https://w3c.github.io/vc-data-integrity/#VerifySubtreeProof

    The hash function is SHA-256, as used by all the current SHoC cryptosuites.

    Ranges of leaves are half-open, [a, b). Every recursion splits a range of
    more than one leaf at the largest power of two strictly less than its
    length, which is what ComputeTreeShape defines. The subtree proof and
    verification functions follow that shape without building the tree.
*/
import { sha256 } from '@noble/hashes/sha256'
import { concatBytes } from '@noble/hashes/utils'

const LEAF_PREFIX = Uint8Array.of(0x00)
const NODE_PREFIX = Uint8Array.of(0x01)

/**
 * Largest power of two strictly less than n, for n > 1.
 * @param {number} n
 * @returns {number}
 */
export function splitPoint (n) {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

/**
 * Leaf hash of a salted statement: H(0x00 || salt || UTF-8(statement)).
 * See MerkleizeSD step 4.
 * @param {Uint8Array} salt
 * @param {string} statement - a canonical N-Quad
 * @returns {Uint8Array}
 */
export function leafHash (salt, statement) {
  return sha256(concatBytes(LEAF_PREFIX, salt, new TextEncoder().encode(statement)))
}

/**
 * Internal node hash: H(0x01 || left || right).
 * @param {Uint8Array} left
 * @param {Uint8Array} right
 * @returns {Uint8Array}
 */
export function nodeHash (left, right) {
  return sha256(concatBytes(NODE_PREFIX, left, right))
}

/**
 * Merkle Tree Hash over an array of leaf hashes (the leaf prefix has already
 * been applied, so a single leaf hash is its own root).
 * @param {Uint8Array[]} leafHashes
 * @returns {Uint8Array}
 */
export function mth (leafHashes) {
  const n = leafHashes.length
  if (n === 0) return sha256(new Uint8Array(0))
  if (n === 1) return leafHashes[0]
  const k = splitPoint(n)
  return nodeHash(mth(leafHashes.slice(0, k)), mth(leafHashes.slice(k)))
}

/**
 * The tree shape for a number of leaves, as nested objects. Internal nodes
 * are { name: 'N_a_b', start: a, end: b, left, right } and leaves are
 * { name: 'Leafj', start: j, end: j + 1 }, using the node names from the
 * spec and SimpleMerkle. The empty tree is null. Only used for checks and to
 * label proof values in the test vector output.
 * @param {number} treeSize
 * @param {number} [start=0] - offset of the first leaf
 * @returns {object|null}
 */
export function computeTreeShape (treeSize, start = 0) {
  if (treeSize === 0) return null
  if (treeSize === 1) return { name: `Leaf${start}`, start, end: start + 1 }
  const k = splitPoint(treeSize)
  return {
    name: `N_${start}_${start + treeSize}`,
    start,
    end: start + treeSize,
    left: computeTreeShape(k, start),
    right: computeTreeShape(treeSize - k, start + k)
  }
}

/**
 * Check that leafIndexes is strictly ascending and within [0, treeSize).
 * @param {number} treeSize
 * @param {number[]} leafIndexes
 */
export function checkLeafIndexes (treeSize, leafIndexes) {
  if (!Number.isInteger(treeSize) || treeSize < 0) {
    throw new Error('treeSize must be a non-negative integer')
  }
  if (!Array.isArray(leafIndexes)) {
    throw new Error('leafIndexes must be an array')
  }
  leafIndexes.forEach((index, i) => {
    if (!Number.isInteger(index) || index < 0 || index >= treeSize) {
      throw new Error(`leaf index ${index} out of range [0, ${treeSize})`)
    }
    if (i > 0 && index <= leafIndexes[i - 1]) {
      throw new Error('leafIndexes must be strictly ascending')
    }
  })
}

// Position of the first element of the sorted array that is >= value.
function lowerBound (sorted, value) {
  let lo = 0
  let hi = sorted.length
  while (lo < hi) {
    const mid = (lo + hi) >>> 1
    if (sorted[mid] < value) lo = mid + 1
    else hi = mid
  }
  return lo
}

// The disclosed leaves within [a, b) are leafIndexes[lo:hi]. Since the
// indexes are strictly ascending, none are disclosed when lo === hi and all
// are disclosed when hi - lo === b - a. Uses binary search rather than
// scanning the range, per the VerifySubtreeProof complexity requirement.
function disclosedRange (leafIndexes, a, b) {
  return [lowerBound(leafIndexes, a), lowerBound(leafIndexes, b)]
}

// Walk the subtree proof traversal of CreateSubtreeProof over [0, treeSize),
// calling emit(a, b) for each maximal undisclosed subtree, in order.
function walkUndisclosed (treeSize, leafIndexes, emit) {
  const agg = (a, b) => {
    const [lo, hi] = disclosedRange(leafIndexes, a, b)
    if (lo === hi) return emit(a, b) // nothing disclosed
    if (hi - lo === b - a) return // everything disclosed
    const k = splitPoint(b - a)
    agg(a, a + k)
    agg(a + k, b)
  }
  if (treeSize > 0) agg(0, treeSize)
}

/**
 * CreateSubtreeProof: the roots of the maximal undisclosed subtrees,
 * depth first, left before right.
 * @param {number} treeSize
 * @param {number[]} leafIndexes - disclosed leaves, strictly ascending
 * @param {Uint8Array[]} leafHashes - all treeSize leaf hashes
 * @returns {Uint8Array[]} subtreeProof
 */
export function createSubtreeProof (treeSize, leafIndexes, leafHashes) {
  checkLeafIndexes(treeSize, leafIndexes)
  if (leafHashes.length !== treeSize) {
    throw new Error('leafHashes length does not match treeSize')
  }
  const subtreeProof = []
  walkUndisclosed(treeSize, leafIndexes, (a, b) => subtreeProof.push(mth(leafHashes.slice(a, b))))
  return subtreeProof
}

/**
 * Names (in the N_a_b / Leafj convention) of the subtree proof elements, in
 * proof order. For readability of the test vector output.
 * @param {number} treeSize
 * @param {number[]} leafIndexes
 * @returns {string[]}
 */
export function subtreeProofNames (treeSize, leafIndexes) {
  checkLeafIndexes(treeSize, leafIndexes)
  const names = []
  walkUndisclosed(treeSize, leafIndexes, (a, b) => names.push(b - a === 1 ? `Leaf${a}` : `N_${a}_${b}`))
  return names
}

/**
 * The number of elements a subtree proof must have for this tree size and set
 * of disclosed leaves. Used by VerifyDerived-SHoC.
 * @param {number} treeSize
 * @param {number[]} leafIndexes
 * @returns {number}
 */
export function expectedProofLength (treeSize, leafIndexes) {
  checkLeafIndexes(treeSize, leafIndexes)
  let count = 0
  walkUndisclosed(treeSize, leafIndexes, () => count++)
  return count
}

/**
 * VerifySubtreeProof: reconstruct the Merkle root from the disclosed leaf
 * hashes and the subtree proof. Throws an error if the proof is malformed
 * (too short, or not fully used). Evaluated sparsely: no tree of size
 * treeSize is built.
 * @param {number} treeSize
 * @param {number[]} leafIndexes - disclosed leaves, strictly ascending
 * @param {Uint8Array[]} disclosedLeafHashes - one per element of leafIndexes
 * @param {Uint8Array[]} subtreeProof
 * @returns {Uint8Array} reconstructedRoot
 */
export function verifySubtreeProof (treeSize, leafIndexes, disclosedLeafHashes, subtreeProof) {
  checkLeafIndexes(treeSize, leafIndexes)
  if (disclosedLeafHashes.length !== leafIndexes.length) {
    throw new Error('disclosedLeafHashes length does not match leafIndexes')
  }
  if (treeSize === 0) {
    if (subtreeProof.length !== 0) {
      throw new Error('subtree proof must be empty for an empty tree')
    }
    return mth([])
  }
  let proofCursor = 0
  const reconstruct = (a, b) => {
    const [lo, hi] = disclosedRange(leafIndexes, a, b)
    if (lo === hi) { // nothing disclosed: value comes from the proof
      if (proofCursor >= subtreeProof.length) {
        throw new Error('subtree proof too short')
      }
      return subtreeProof[proofCursor++]
    }
    if (hi - lo === b - a) { // fully disclosed: recompute from the leaves
      return mth(disclosedLeafHashes.slice(lo, hi))
    }
    const k = splitPoint(b - a)
    const left = reconstruct(a, a + k)
    const right = reconstruct(a + k, b)
    return nodeHash(left, right)
  }
  const reconstructedRoot = reconstruct(0, treeSize)
  if (proofCursor !== subtreeProof.length) {
    throw new Error('subtree proof not fully consumed')
  }
  return reconstructedRoot
}
