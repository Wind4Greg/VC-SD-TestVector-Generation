/*
    Check to see if our example mandatory pointers work the way we thought they
    should and generate a test vector.

*/

import { repoPath } from './lib/paths.js'
import { mkdir, readFile, writeFile } from 'fs/promises'
import jsPointer from 'json-pointer'
// Set input file and output directory here
// const dirsAndFiles = {
//   outputDir: repoPath('output/ecdsa-sd-2023/'),
//   inputFile: repoPath('input/windDoc.json'),
//   mandatoryFile: repoPath('input/windMandatory.json')
// }
const dirsAndFiles = {
  outputDir: repoPath('output/ecdsa-sd-2023/employ/'),
  inputFile: repoPath('input/employmentAuth.json'),
  mandatoryFile: repoPath('input/employMandatory.json')
}
// const dirsAndFiles = {
//   outputDir: repoPath('output/ecdsa-sd-2023/prc/'),
//   inputFile: repoPath('input/prCredUnsigned.json'),
//   mandatoryFile: repoPath('input/prCredMandatory.json')
// }
// Create output directory for the test vectors
const baseDir = dirsAndFiles.outputDir
const status = await mkdir(baseDir, { recursive: true })

// Read input document from a file or just specify it right here.
const document = JSON.parse(
  await readFile(
    dirsAndFiles.inputFile
  )
)

const pointers = JSON.parse(
  await readFile(
    dirsAndFiles.mandatoryFile
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
