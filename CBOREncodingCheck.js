/*
    Different CBOR libraries produce different outputs due to tagging Uint8Arrays.
    Seeing if we can turn it off and if outputs are the same.
*/
import { repoPath } from './lib/paths.js'
import { readFile } from 'fs/promises'
import cbor from 'cbor'
import { encode } from 'cborg'
import { Encoder } from 'cbor-x'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { encode as encode2 } from 'cbor2'

const data = JSON.parse(
  await readFile(repoPath('input/cborCheckInput.json')))
const baseSignature = hexToBytes(data.baseSignature)
const hmacKey = hexToBytes(data.hmacKeyString)
const signatures = data.signatures.map(sigHex => hexToBytes(sigHex))
const mandatoryPointers = data.mandatoryPointers
const components = [baseSignature, hmacKey, signatures, mandatoryPointers]

const cborThing = await cbor.encodeAsync(components)
console.log('CBOR library encoding hex:')
const cborThingHex = bytesToHex(cborThing)
console.log(cborThingHex)

const cborgThing = await encode(components)
console.log('CBORG library encoding hex:')
const cborgThingHex = bytesToHex(cborgThing)
console.log(cborgThingHex)

const cborXEncoder = new Encoder({ tagUint8Array: false })
const cborxThing = cborXEncoder.encode(components)
console.log('CBOR-X library encoding hex:')
const cborxThingHex = bytesToHex(cborxThing)
console.log(cborxThingHex)

console.log(`cborx == cborg? ${cborgThingHex === cborxThingHex}`)
console.log(`cbor == cborg? ${cborThingHex === cborxThingHex}`)

const byteData = [new Uint8Array([0,1,2,3]), new Uint8Array([4, 5, 6, 7])]
const textData = ["hello", "world"]
const combination = [byteData, textData]

const cborThing2 = await cbor.encodeAsync(combination)
console.log('Ex 2 CBOR library encoding hex:')
const cborThingHex2 = bytesToHex(cborThing2)
console.log(cborThingHex2)

const cborgThing2 = await encode(combination)
console.log('Ex 2 CBORG library encoding hex:')
const cborgThingHex2 = bytesToHex(cborgThing2)
console.log(cborgThingHex2)

const cborXEncoder2 = new Encoder({ tagUint8Array: false })
const cborxThing2 = cborXEncoder2.encode(combination)
console.log('Ex 2 CBOR-X library encoding hex:')
const cborxThingHex2 = bytesToHex(cborxThing2)
console.log(cborxThingHex2)

const cbor2Thing2 = encode2(combination)
console.log('Ex 2 CBOR2 library encoding hex:')
const cbor2ThingHex2 = bytesToHex(cbor2Thing2)
console.log(cbor2ThingHex2)
