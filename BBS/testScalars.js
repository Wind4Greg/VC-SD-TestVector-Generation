/*  Generate some random BLS12-381 G1 appropriate scalars in hex.
    Use them where you need random scalars for test vectors!
    Generalized to write to a file.
*/
import { repoPath } from '../lib/paths.js';
import { calculate_random_scalars } from "./lib/BBS.js";
import { mkdir, readFile, writeFile } from 'fs/promises'


const baseDir = repoPath('BBS/temp/rand_scalars/');
await mkdir(baseDir, { recursive: true })

const count = 1000;
const scalars = calculate_random_scalars(count);
const hexScalars = scalars.map(scalar => scalar.toString(16));
console.log('Generating and writing random BLS12-381 G1 scalar values:');
// console.log(JSON.stringify(hexScalars, null, 2));
const myObject = {proverNyms: hexScalars}; // You can change the name or whatever
await writeFile(baseDir + 'nymSecrets.json', JSON.stringify(myObject, null, 2))
