/* checking HMAC based deterministic random  bit generator  algorithm from 
   NIST SP 800-90A Rev. 1.

   Step 1: get it to run (DONE)
   Step 2: try NIST test vectors


Test Vector Extracted from: 
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_DRBG.pdf

HMAC_DRBG
Requested Security Strength = 128
Requested Hash Algorithm = SHA-256
prediction_resistance_flag = "NOT ENABLED"
EntropyInput = 000102 03040506 0708090A 0B0C0D0E 0F101112 13141516 1718191A 1B1C1D1E
1F202122 23242526 2728292A 2B2C2D2E 2F303132 33343536

Nonce = 20212223 24252627
requested_number_of_bits = 512
returned_bits is
D67B8C17 34F46FA3 F763CF57 C6F9F4F2
DC1089BD 8BC1F6F0 23950BFC 56176352 08C85012 38AD7A44
00DEFEE4 6C640B61 AF77C2D1 A3BFAA90 EDE5D207 406E5403

Second call to generate
returned_bits is
8FDAEC20 F8B42140 7059E358 8920DA7E
DA9DCE3C F8274DFA 1C59C108 C1D0AA9B 0FA38DA5 C792037C
4D33CD07 0CA7CD0C 5608DBA8 B8856546 39DE2187 B74CB263
*/

import DRBG from 'hmac-drbg';
import hash from 'hash.js';
 
const d = new DRBG({
  hash: hash.sha256,
  entropy: '0123456789abcdef0123456789abcdef0123456789abcdef',
  nonce: '0123456789abcdef',
  pers: '0123456789abcdef' /* or `null` */
});

const d2 = new DRBG({
  hash: hash.sha256,
  entropy: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233343536',
  nonce: '20212223 24252627',
  pers: null /* or `null` */
});
console.log("First call to generate:");
console.log(d2.generate(64, 'hex')); // 64 bytes = 512 bits
console.log("Second call to generate:");
console.log(d2.generate(64, 'hex')); // 64 bytes = 512 bits