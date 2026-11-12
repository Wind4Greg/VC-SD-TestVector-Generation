/*
    Registry of example credentials used to generate test vectors, and
    command line selection of which examples a script should run.

    Each example has an unsigned document, the issuer's mandatory pointers,
    and the holder's selective pointers.

    Scripts call selectExamples() with the examples they support. With no
    command line option every supported example is run; otherwise use
        --example <name>     (may be repeated, or given as a comma list)
*/
import { parseArgs } from 'node:util'
import { repoPath } from './paths.js'

function example (unsigned, mandatory, selective) {
  return {
    unsigned: repoPath(unsigned),
    mandatory: repoPath(mandatory),
    selective: repoPath(selective)
  }
}

export const examples = {
  wind: example('input/windDoc.json', 'input/windMandatory.json', 'input/windSelective.json'),
  employ: example('input/employmentAuth.json', 'input/employMandatory.json', 'input/employSelective.json'),
  prc: example('input/prCredUnsigned.json', 'input/prCredMandatory.json', 'input/prCredSelective.json'),
  license: example('input/license.json', 'input/licenseMandatory.json', 'input/licenseSelective.json'),
  tree: example('input/treeDoc.json', 'input/treeMandatory.json', 'input/treeSelective.json')
}

/**
 * Determine which examples to run from the command line.
 * @param {string[]} supported - names of the examples this script supports
 * @returns {string[]} the example names to run, in `supported` order
 */
export function selectExamples (supported) {
  const { values } = parseArgs({
    options: { example: { type: 'string', short: 'e', multiple: true } },
    strict: true
  })
  if (!values.example) {
    return supported
  }
  const requested = values.example.flatMap(e => e.split(',')).map(e => e.trim()).filter(Boolean)
  const unknown = requested.filter(name => !supported.includes(name))
  if (unknown.length > 0) {
    console.error(`Unsupported example(s): ${unknown.join(', ')}. This script supports: ${supported.join(', ')}`)
    process.exit(1)
  }
  return supported.filter(name => requested.includes(name))
}
