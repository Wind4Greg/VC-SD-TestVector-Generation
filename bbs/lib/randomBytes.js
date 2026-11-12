
export function randomBytes(bytesLength = 32) {
    return crypto.getRandomValues(new Uint8Array(bytesLength));
}