async function registerWebauthn(username) {
    let publicKeyCredentialCreationOptions = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: {
            name: location.hostname,
            id: location.hostname,
        },
        user: {
            id: crypto.getRandomValues(new Uint8Array(64)),
            name: username,
            displayName: username,
        },
        pubKeyCredParams: [
            {
                alg: -7,
                type: "public-key"
            },
            {
                alg: -257,
                type: "public-key"
            }
        ],
        authenticatorSelection: {
            userVerification: "preferred",
            requireResidentKey: false,
            residentKey: "preferred"
        },
        attestation: "none",
        extensions: {
            credProps: true
        }
    };
    let credential, authData;
    try {
        credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        });
        authData = cbor.decode(credential.response.attestationObject).authData;
        let credentialId = credential.rawId;
        let dataView = new DataView(new ArrayBuffer(2));
        authData.slice(53, 55).forEach((value, index) => dataView.setUint8(index, value));
        let credentialIdLength = dataView.getUint16();
        let publicKey = authData.slice(55 + credentialIdLength);
        let backupEligible = authData[32].toString(2).padStart(8, "0").slice(4, 5) == "1";
        return {
            credentialId,
            publicKey,
            backupEligible
        }
    } catch { return false; }
};
async function authenticateWebauthn(challenge) {
    let publicKeyCredentialRequestOptions = {
        challenge: challenge,
        timeout: 60000,
        userVerification: "preferred"
    };
    let assertion;
    try {
        assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        });
    } catch { return false; }
    return assertion;
}

function ab2h(buffer) {
    return Array.from(new Uint8Array(buffer)).map(a => a.toString(16).padStart(2, "0")).join("")
}
function h2u8(hex) {
    return Uint8Array.from(hex.match(/.{1,2}/g), c => parseInt(c, 16));
}