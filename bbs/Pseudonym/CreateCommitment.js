/*
    Walking through the steps for producing a commitment with proof
    for a *proverNym* for use in Pseudonym feature.
*/
import { repoPath } from '../../lib/paths.js'
import { mkdir, readFile, writeFile } from 'fs/promises'
import { API_ID_PSEUDONYM_BBS_SHA, hexToBytes, bytesToHex, numberToHex } from '../lib/BBS.js'
import {NymCommit} from '../lib/PseudonymBBS.js'

// Create output directory for the test vectors
const baseDir = repoPath('bbs/output/Pseudonym/license/')
await mkdir(baseDir, { recursive: true })
const proverInfo = JSON.parse(
  await readFile(repoPath('input/proverNym.json')))
console.log(proverInfo.proverNymHex)
const proverNym = BigInt('0x' + proverInfo.proverNymHex)
// NymCommit(messages, prover_nym, api_id, rand_scalars = calculate_random_scalars)
const [commitWithProofOcts, secretProverBlind] = await NymCommit([], proverNym, API_ID_PSEUDONYM_BBS_SHA);
const commitInfo = {
  secretProverBlind: numberToHex(secretProverBlind, 32),
  commitmentWithProof: bytesToHex(commitWithProofOcts)
}
await writeFile(baseDir + 'commitmentInfo.json', JSON.stringify(commitInfo, null, 2))
