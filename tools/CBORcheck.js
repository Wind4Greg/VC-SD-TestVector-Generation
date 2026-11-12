/*
    Different CBOR libraries produce different outputs, but can be read by each
    other if they are up to date.
*/
import cbor from 'cbor'
import { encode, decode } from 'cborg'
import { base64url } from 'multiformats/bases/base64'

// This derived proof was encoded with cborg 2.0.5
const sample1 = 'u2V0BhVhAWibkVjFQTPQvRFt1HwFnfVxLM9ibkNZ1BCkQOox8pUqByjZQedlncpIKNeVh72Y4gvvU6J1NEMyrDOeMX32RA1gjgCQCKnLOGbY_FuM-ASpSkkOxsIR2E8n7Ml2q1UQ6tEwzi5OGWEBtAwxySlwwASjXlYLoLwyjdsIRYUa05OQzE0P4skx1-QJKi8HtGcJHtJfOTn7RhWKC0nkXODvUAChvnKDVY02TWEClAeVhEaVRWS_5ZfU6MlgnX07DuKm9XBS-b3RKfciM1Eu7L2mvkMebfBWVUw9WkuqNL4Tz-MkN4lXmljRt8r8DWEA78ePS_Gy4lnOlUa2CgworZmUYq-Etff-9QK90v4xOWzNWvaILdcmkJs5zwH9b86f5yxos_NRK-VIO015zVlWTWEB2bYe3iy_95zezUdGp66X77IQbHhKunDI1BF0trlkrIkOCqviH4S1U3Nz4n5WWW8qsc3zAEq1Spquojg2mevHtWEA5EwtdjPeXn07NztIOTZ6PtyWt6v0Gfp5oFRAbvvcCpDnptz6gZd56Z6TBkI0eMUs4RI2g2rup607wVFuIUdvgWEC9Jb2rzxEtn2VZ2DZl4r5x_5wWVT8-OrHVtRUBcwdDe1_gl-PYhQ26vLcTN87eyPdVhft0O-URO1PQdifev4NKpQBYIOGCDmZ9TBxEtWeCI9oVmRt0eHRGAaoOXx08gxL2IQt_AVggk0AeXgJ4e6m1XsV5-xFud0L_1mUjZ9Mffhg5aZGTyDkCWCBWRS4GuU5oQsZVBYkPgz-pbltwoQdYY1s6s8D-oA4orANYIJEdvfdRibsv05I3pv8e6S1aUuAuBpGQHLhrYj4QX0knBFggQ-qOZUDlozRsGk46ux9gp9fjT28Fy3g3nctmMoqi_U2MAgMEBQkKDA0ODxAR'
const sample1Bytes = base64url.decode(sample1)
// console.log(proofValueBytes.length);
// check header bytes are: 0xd9, 0x5d, and 0x01
if (sample1Bytes[0] !== 0xd9 || sample1Bytes[1] !== 0x5d || sample1Bytes[2] !== 0x01) {
  throw new Error('Invalid proofValue header')
}
const decodeThing1 = cbor.decode(sample1Bytes.slice(3))
console.log(decodeThing1)
const options = { useMaps: true }
const decodeThing1b = decode(sample1Bytes.slice(3), options)
console.log(decodeThing1b)

// cbor 9.0.1 library encoded derived proof
const sample2 = 'u2V0BhdhAWEBaJuRWMVBM9C9EW3UfAWd9XEsz2JuQ1nUEKRA6jHylSoHKNlB52Wdykgo15WHvZjiC-9TonU0QzKsM54xffZED2EBYI4AkAipyzhm2PxbjPgEqUpJDsbCEdhPJ-zJdqtVEOrRMM4uThthAWEBtAwxySlwwASjXlYLoLwyjdsIRYUa05OQzE0P4skx1-QJKi8HtGcJHtJfOTn7RhWKC0nkXODvUAChvnKDVY02T2EBYQKUB5WERpVFZL_ll9ToyWCdfTsO4qb1cFL5vdEp9yIzUS7svaa-Qx5t8FZVTD1aS6o0vhPP4yQ3iVeaWNG3yvwPYQFhAO_Hj0vxsuJZzpVGtgoMKK2ZlGKvhLX3_vUCvdL-MTlszVr2iC3XJpCbOc8B_W_On-csaLPzUSvlSDtNec1ZVk9hAWEB2bYe3iy_95zezUdGp66X77IQbHhKunDI1BF0trlkrIkOCqviH4S1U3Nz4n5WWW8qsc3zAEq1Spquojg2mevHt2EBYQDkTC12M95efTs3O0g5Nno-3Ja3q_QZ-nmgVEBu-9wKkOem3PqBl3npnpMGQjR4xSzhEjaDau6nrTvBUW4hR2-DYQFhAvSW9q88RLZ9lWdg2ZeK-cf-cFlU_Pjqx1bUVAXMHQ3tf4Jfj2IUNury3EzfO3sj3VYX7dDvlETtT0HYn3r-DSqUA2EBYIOGCDmZ9TBxEtWeCI9oVmRt0eHRGAaoOXx08gxL2IQt_AdhAWCCTQB5eAnh7qbVexXn7EW53Qv_WZSNn0x9-GDlpkZPIOQLYQFggVkUuBrlOaELGVQWJD4M_qW5bcKEHWGNbOrPA_qAOKKwD2EBYIJEdvfdRibsv05I3pv8e6S1aUuAuBpGQHLhrYj4QX0knBNhAWCBD6o5lQOWjNGwaTjq7H2Cn1-NPbwXLeDedy2YyiqL9TYwCAwQFCQoMDQ4PEBE'
const sample2Bytes = base64url.decode(sample1)
// console.log(proofValueBytes.length);
// check header bytes are: 0xd9, 0x5d, and 0x01
if (sample2Bytes[0] !== 0xd9 || sample2Bytes[1] !== 0x5d || sample2Bytes[2] !== 0x01) {
  throw new Error('Invalid proofValue header')
}
const decodeThing2 = cbor.decode(sample2Bytes.slice(3))
console.log(decodeThing2)
const decodeThing2b = decode(sample2Bytes.slice(3), options)
console.log(decodeThing2b)
