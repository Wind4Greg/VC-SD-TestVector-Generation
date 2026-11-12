# Notes on Test Vectors for BBS

### Optional Feature Tags, Parameters, and inputs


| Name | proof type | header bytes | serialized values | api_id | extra inputs |
|:---|:---|:---|:--|:--|:--|
| BBS | base |`0xd9`, `0x5d`, and `0x02`|bbsSignature, bbsHeader, publicKey, hmacKey, and mandatoryPointers | BBS-SHA | N/A |
| BBS | disclosure | `0xd9`, `0x5d`, and `0x03` |bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, and presentationHeader| BBS-SHA | N/A |
| BBS Anonymous Holder Binding | base |`0xd9`, `0x5d`, and `0x04` | bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers, and signerBlind | BLIND_BBS | commitment with proof for holder secret|
|BBS Anonymous Holder Binding | disclosure | `0xd9`, `0x5d`, and `0x05` | bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, and presentationHeader | BLIND_BBS | holder secret, proverBlind |
| BBS Pseudonyms with Issuer-known PID | base |`0xd9`, `0x5d`, and `0x06` | bbsSignature, bbsHeader, publicKey, hmacKey, and mandatoryPointers, pid | PSEUDO_BBS | issuer generates pid |
| BBS Pseudonyms with Issuer-known PID | disclosure | `0xd9`, `0x5d`, and `0x07` | bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader, and pseudonym | PSEUDO_BBS | verifier id |
| BBS Pseudonyms with Hidden PID | base | `0xd9`, `0x5d`, and `0x08` | bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers, and signerBlind | PSEUDO_BBS | commitment with proof for pid |
| BBS Pseudonyms with Hidden PID | disclosure | `0xd9`, `0x5d`, and `0x09` |bbsProof, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader, and pseudonym | PSEUDO_BBS | pid, proverBlind, verifier id |
