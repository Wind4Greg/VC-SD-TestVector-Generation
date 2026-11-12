/*
    Repository-root-relative paths for inputs and outputs.

    Every script resolves its input and output locations through repoPath() so
    that it behaves the same no matter which directory it is launched from.
*/
import { fileURLToPath } from 'node:url'
import path from 'node:path'

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Resolve a path given relative to the repository root.
 * A trailing '/' is preserved so directory paths can be used as
 * `dir + 'file.json'`.
 * @param {string} rel - path relative to the repository root
 * @returns {string} absolute path
 */
export function repoPath (rel = '') {
  const abs = path.resolve(repoRoot, rel)
  return rel.endsWith('/') ? abs + path.sep : abs
}
