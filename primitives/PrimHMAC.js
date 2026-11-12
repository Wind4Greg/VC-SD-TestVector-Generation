/*
    Checking SD-Primitive: hmacIdCanonize
    function hmacIdCanonize({document, options, hmac, labelMap} = {})
    The labelMap is optional and if present will be used instead of the hmac function.
    This returns a sorted *array* of quads.
    hmac is a HMAC function that has already been set up with a key. See below for
    usage.
*/

import { repoPath } from '../lib/paths.js'
import { readFile, writeFile } from 'fs/promises'
import { createHmac, hmacIdCanonize } from '@digitalbazaar/di-sd-primitives'
import jsonld from 'jsonld'
import { localLoader } from '../documentLoader.js'
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils'

jsonld.documentLoader = localLoader // Local loader for JSON-LD

// Read input document from a file or just specify it right here.
const document = JSON.parse(
  await readFile(
    repoPath('input/windDoc.json')
  )
)

// Need an HMAC string
const hmacKeyString = '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
const hmacKey = hexToBytes(hmacKeyString)
// async function createHmac({algorithm = 'HS256', key} = {})
const hmac = await createHmac({ algorithm: 'HS256', key: hmacKey })
const options = {}

const result = await hmacIdCanonize({ document, options, hmac })
console.log(result)
console.log(`Result is an array? ${Array.isArray(result)}`)

/*

Generated output:

[
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#boards> _:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 .\n',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#boards> _:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc .\n',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sailNumber> "Earth101" .\n',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 .\n',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw .\n',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ .\n',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk .\n',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#type> "VerifiableCredential" .\n',
  '_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#sailName> "Osprey" .\n',
  '_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#size> "5.5E0"^^<http://www.w3.org/2001/XMLSchema#double> .\n',
  '_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#year> "2023"^^<http://www.w3.org/2001/XMLSchema#integer> .\n',
  '_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#boardName> "Tillo Custom" .\n',
  '_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#brand> "Tillo" .\n',
  '_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#year> "2019"^^<http://www.w3.org/2001/XMLSchema#integer> .\n',
  '_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#sailName> "Eagle-FR" .\n',
  '_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#size> "6.1E0"^^<http://www.w3.org/2001/XMLSchema#double> .\n',
  '_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#year> "2023"^^<http://www.w3.org/2001/XMLSchema#integer> .\n',
  '_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#sailName> "Eagle-FR" .\n',
  '_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#size> "7"^^<http://www.w3.org/2001/XMLSchema#integer> .\n',
  '_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#year> "2020"^^<http://www.w3.org/2001/XMLSchema#integer> .\n',
  '_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#sailName> "Eagle-FR" .\n',
  '_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#size> "7.8E0"^^<http://www.w3.org/2001/XMLSchema#double> .\n',
  '_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#year> "2023"^^<http://www.w3.org/2001/XMLSchema#integer> .\n',
  '_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#boardName> "CompFoil170" .\n',
  '_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#brand> "Tillo" .\n',
  '_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#year> "2022"^^<http://www.w3.org/2001/XMLSchema#integer> .\n'
]

My output almost exactly the same except for '\n', i.e., CR at the end of each line:

[
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#boards> _:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 .',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#boards> _:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc .',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sailNumber> "Earth101" .',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 .',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw .',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ .',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#sails> _:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk .',
  '_:u3Lv2QpFgo-YAegc1cQQKWJFW2sEjQF6FfuZ0VEoMKHg <https://windsurf.grotto-networking.com/selective#type> "VerifiableCredential" .',
  '_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#sailName> "Osprey" .',
  '_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#size> "5.5E0"^^<http://www.w3.org/2001/XMLSchema#double> .',
  '_:u4YIOZn1MHES1Z4Ij2hWZG3R4dEYBqg5fHTyDEvYhC38 <https://windsurf.grotto-networking.com/selective#year> "2023"^^<http://www.w3.org/2001/XMLSchema#integer> .',
  '_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#boardName> "Tillo Custom" .',
  '_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#brand> "Tillo" .',
  '_:uQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U0 <https://windsurf.grotto-networking.com/selective#year> "2019"^^<http://www.w3.org/2001/XMLSchema#integer> .',
  '_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#sailName> "Eagle-FR" .',
  '_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#size> "6.1E0"^^<http://www.w3.org/2001/XMLSchema#double> .',
  '_:uVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKw <https://windsurf.grotto-networking.com/selective#year> "2023"^^<http://www.w3.org/2001/XMLSchema#integer> .',
  '_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#sailName> "Eagle-FR" .',
  '_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#size> "7"^^<http://www.w3.org/2001/XMLSchema#integer> .',
  '_:ufUWJRHQ9j1jmUKHLL8k6m0CZ8g4v73gOpaM5kL3ZACQ <https://windsurf.grotto-networking.com/selective#year> "2020"^^<http://www.w3.org/2001/XMLSchema#integer> .',
  '_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#sailName> "Eagle-FR" .',
  '_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#size> "7.8E0"^^<http://www.w3.org/2001/XMLSchema#double> .',
  '_:uk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDk <https://windsurf.grotto-networking.com/selective#year> "2023"^^<http://www.w3.org/2001/XMLSchema#integer> .',
  '_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#boardName> "CompFoil170" .',
  '_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#brand> "Tillo" .',
  '_:ukR2991GJuy_Tkjem_x7pLVpS4C4GkZAcuGtiPhBfSSc <https://windsurf.grotto-networking.com/selective#year> "2022"^^<http://www.w3.org/2001/XMLSchema#integer> .'
]
*/
