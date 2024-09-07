HTMLInputElement.prototype.secureValue = async function() {
    let keypair = nacl.sign.keyPair.fromSeed(new Uint8Array(await crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt: new Uint8Array(32),
        iterations: 100000,
        hash: "SHA-256"
    }, await crypto.subtle.importKey("raw", new TextEncoder().encode(this.value), "PBKDF2", false, ["deriveBits"]), 256)));
    let hexToU8A = (hex) => Uint8Array.from(hex.match(/.{1,2}/g).map(a => parseInt(a, 16)));
    if (this.dataset.challenge) return nacl.sign.detached(hexToU8A(this.dataset.challenge), keypair.secretKey);
    return keypair.publicKey;
};