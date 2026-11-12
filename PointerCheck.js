/*
    Check to see if our example mandatory pointers work the way we thought they
    should and generate a test vector.

*/

import { repoPath } from './lib/paths.js'
import { examples, selectExamples } from './lib/examples.js'
import { mkdir, readFile, writeFile } from 'fs/promises'
import jsPointer from 'json-pointer'
// Output directory for each supported example; choose examples with --example
const outputDirs = {
  wind: repoPath('output/ecdsa-sd-2023/'),
  employ: repoPath('output/ecdsa-sd-2023/employ/'),
  prc: repoPath('output/ecdsa-sd-2023/prc/')
}

for (const name of selectExamples(Object.keys(outputDirs))) {
  console.log(`*** Example: ${name} ***`)
  await generate(examples[name], outputDirs[name])
}

async function generate (example, baseDir) {
  const status = await mkdir(baseDir, { recursive: true })

  // Read input document from a file or just specify it right here.
  const document = JSON.parse(
    await readFile(
      example.unsigned
    )
  )

  const pointers = JSON.parse(
    await readFile(
      example.mandatory
    )
  )

  console.log(document)
  console.log(pointers)
  pointers.forEach(function (pointer) {
    const has = jsPointer.has(document, pointer)
    console.log(`${has} Document containers ${pointer}`)
  })
  const pointerValues = []
  pointers.forEach(function (pointer) {
    const value = jsPointer.get(document, pointer)
    console.log(`Pointer ${pointer} has value:`)
    console.log(value)
    const entry = { pointer, value }
    pointerValues.push(entry)
  })
  await writeFile(baseDir + 'addPointerValues.json', JSON.stringify(pointerValues, null, 2))
}
