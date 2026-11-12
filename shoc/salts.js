/*
    DeriveSaltsSD from the VC-Data-Integrity specification:
    https://w3c.github.io/vc-data-integrity/#DeriveSaltsSD

    salts[i] is the first 16 bytes (half the SHA-256 output) of
    HMAC-SHA-256(saltSeed, uint64be(i)). Used by the issuer when creating the
    base proof and by the holder when creating a derived proof. Verifiers
    never derive salts; they use the salts carried in the derived proof.
*/
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'

export const SALT_LENGTH = 16 // half the SHA-256 output length

/**
 * The 8-byte big-endian unsigned integer encoding of n.
 * @param {number} n - a non-negative safe integer
 * @returns {Uint8Array}
 */
export function uint64be (n) {
  const bytes = new Uint8Array(8)
  new DataView(bytes.buffer).setBigUint64(0, BigInt(n))
  return bytes
}

/**
 * DeriveSaltsSD: derive count salts from a salt seed.
 * @param {Uint8Array} saltSeed - 16 to 32 bytes
 * @param {number} count - a non-negative integer
 * @returns {Uint8Array[]} count salts of SALT_LENGTH bytes
 */
export function deriveSalts (saltSeed, count) {
  if (!(saltSeed instanceof Uint8Array) || saltSeed.length < 16 || saltSeed.length > 32) {
    throw new Error('saltSeed must be 16 to 32 bytes')
  }
  if (!Number.isInteger(count) || count < 0) {
    throw new Error('count must be a non-negative integer')
  }
  const salts = []
  for (let i = 0; i < count; i++) {
    salts.push(hmac(sha256, saltSeed, uint64be(i)).slice(0, SALT_LENGTH))
  }
  return salts
}
