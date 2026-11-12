/*
    Checking SD-Primitives:
    async function skolemizeCompactJsonLd({document, options})

    async function toDeskolemizedNQuads({document, options})

    async function labelReplacementCanonicalizeNQuads({nquads, labelMapFactoryFunction, options})
*/

import { repoPath } from '../lib/paths.js'
import { readFile, writeFile } from 'fs/promises'
import {
  skolemizeCompactJsonLd, toDeskolemizedNQuads, createHmac,
  createHmacIdLabelMapFunction, labelReplacementCanonicalizeNQuads
} from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from '../lib/documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read input document from a file or just specify it right here.
const document = JSON.parse(
  await readFile(
    repoPath('input/windDoc.json')
  )
)

const options = { documentLoader: localLoader }

// This is the first step in canonicalizeAndGroup major function
const skolemThings = await skolemizeCompactJsonLd({ document, options })
console.log('Skolemized document (compact and expanded)')
console.log(JSON.stringify(skolemThings, null, 2))

// Second step in canonicalizeAndGroup major function
const deSkQuads = await toDeskolemizedNQuads({ document: skolemThings.expanded, options })
console.log('\ndeskolemized quads:')
console.log(deSkQuads)

// Third step
// Need an HMAC string
const hmacKeyString = '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
const hmacKey = hexToBytes(hmacKeyString)
const hmac = await createHmac({ key: hmacKey })
const labelMapFactoryFunction = createHmacIdLabelMapFunction({ hmac })
const { labelMap, nquads } = await labelReplacementCanonicalizeNQuads({
  nquads: deSkQuads, labelMapFactoryFunction, options
})
console.log(nquads)
console.log(labelMap)
