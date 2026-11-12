/*
    Walking through the steps for producing a commitment with proof
    for a *holderSecret* for use in either Anonymous Holder Binding feature.
*/
import { repoPath } from '../../lib/paths.js'
import { mkdir, readFile, writeFile } from 'fs/promises'
import { API_ID_BLIND_BBS_SHA,  hexToBytes, bytesToHex, numberToHex } from '../lib/BBS.js'
import {commit} from '../lib/BlindBBS.js'

// Create output directory for the test vectors
const baseDir = repoPath('bbs/output/HolderBinding/license/')
await mkdir(baseDir, { recursive: true })
const holderInfo = JSON.parse(
  await readFile(repoPath('input/holderSecret.json')))
console.log(holderInfo.holderSecretHex)
const holderSecret = hexToBytes(holderInfo.holderSecretHex)
const [commitWithProofOcts, secretProverBlind] = await commit([holderSecret], API_ID_BLIND_BBS_SHA);
const commitInfo = {
  secretProverBlind: numberToHex(secretProverBlind, 32),
  commitmentWithProof: bytesToHex(commitWithProofOcts)
}
await writeFile(baseDir + 'commitmentInfo.json', JSON.stringify(commitInfo, null, 2))
