/*
    Run the test vector generation pipeline for one or all SD approaches.

    Usage:
      node tools/generate.js <sic|shoc|bbs|all> [--example <name>]... [--verify-only]

    Each approach's steps run in order (add base, derive, verify base, verify
    derived). --example (or -e, repeatable or comma separated) limits which
    examples are generated; groups that don't support any of the requested
    examples are skipped. --verify-only runs just the verification steps
    against the committed test vectors, without regenerating anything.

    Exits non-zero if any step fails or reports "verified: false".
*/
import { spawnSync } from 'node:child_process'
import { parseArgs } from 'node:util'
import { repoPath } from '../lib/paths.js'

// Steps for each group, in pipeline order. `examples` lists the examples the
// group's scripts support; `exampleArg` says whether they accept --example
// (the BBS feature scripts only use the license example and take no options).
const groups = {
  sic: {
    examples: ['wind', 'employ', 'prc'],
    exampleArg: true,
    steps: ['sic/AddBaseSteps.js', 'sic/PointerCheck.js', 'sic/DeriveSteps.js',
      'sic/VerifyBaseSteps.js', 'sic/VerifyDeriveSteps.js']
  },
  shoc: {
    examples: ['employ'],
    exampleArg: true,
    steps: ['shoc/AddBaseSteps.js', 'shoc/DeriveSteps.js',
      'shoc/VerifyBaseSteps.js', 'shoc/VerifyDeriveSteps.js']
  },
  'bbs/Baseline': {
    examples: ['wind', 'prc'],
    exampleArg: true,
    steps: ['AddBaseSteps', 'DeriveSteps', 'VerifyBaseSteps', 'VerifyDeriveSteps']
      .map(s => `bbs/Baseline/${s}.js`)
  }
}
for (const feature of ['HolderBinding', 'Pseudonym', 'PseudonymHB']) {
  groups[`bbs/${feature}`] = {
    examples: ['license'],
    exampleArg: false,
    steps: ['CreateCommitment', 'AddBaseSteps', 'VerifyBaseSteps', 'DeriveSteps', 'VerifyDeriveSteps']
      .map(s => `bbs/${feature}/${s}.js`)
  }
}

const approaches = {
  sic: ['sic'],
  shoc: ['shoc'],
  bbs: ['bbs/Baseline', 'bbs/HolderBinding', 'bbs/Pseudonym', 'bbs/PseudonymHB']
}
approaches.all = [...approaches.sic, ...approaches.shoc, ...approaches.bbs]

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    example: { type: 'string', short: 'e', multiple: true },
    'verify-only': { type: 'boolean', default: false }
  }
})
const approach = positionals[0]
if (positionals.length !== 1 || !approaches[approach]) {
  console.error(`Usage: node tools/generate.js <${Object.keys(approaches).join('|')}> [--example <name>]... [--verify-only]`)
  process.exit(2)
}
const requested = values.example?.flatMap(e => e.split(',')).map(e => e.trim()).filter(Boolean)
const isVerifyStep = step => /\/Verify[A-Za-z]*Steps\.js$/.test(step)

let failures = 0
for (const name of approaches[approach]) {
  const group = groups[name]
  const examples = requested ? group.examples.filter(e => requested.includes(e)) : group.examples
  if (examples.length === 0) {
    console.log(`=== ${name}: skipped (supports ${group.examples.join(', ')})`)
    continue
  }
  const args = requested && group.exampleArg ? ['--example', examples.join(',')] : []
  const steps = values['verify-only'] ? group.steps.filter(isVerifyStep) : group.steps
  for (const step of steps) {
    console.log(`=== ${step} ${args.join(' ')}`.trimEnd())
    const result = spawnSync(process.execPath, [repoPath(step), ...args], {
      stdio: ['ignore', 'pipe', 'inherit'],
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024
    })
    process.stdout.write(result.stdout ?? '')
    const verifyFailed = /verified: false/i.test(result.stdout ?? '')
    if (result.status !== 0 || verifyFailed) {
      failures++
      console.error(`*** FAILED: ${step}${verifyFailed ? ' (verification failed)' : ` (exit ${result.status})`}`)
      break // later steps in this group depend on this one
    }
  }
}
if (failures > 0) {
  console.error(`\n${failures} group(s) failed`)
  process.exit(1)
}
console.log(`\nAll ${values['verify-only'] ? 'verification' : 'generation'} steps passed.`)
