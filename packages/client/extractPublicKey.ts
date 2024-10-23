import { Buffer } from 'buffer';
import { Decoder } from 'cbor-web';


export interface PublicKey {
    aaguid: Buffer;
    signCount: Buffer;
    credentialId: Buffer;
    kty: number;
    alg: number;
    x: Buffer;
    y: Buffer;
    publicKey: Buffer;
}

/**
 * Extracts the public key from the attestationObject
 * 
 * @param {Buffer} attestationObject - The CBOR encoded attestation object
 * @returns {Promise<Buffer>} - The extracted public key
 */
export async function extractPublicKey(attestationObject): Promise<PublicKey> {
    const decodedAttestationObject = await Decoder.decodeFirst(attestationObject);
    const authenticatorData = decodedAttestationObject.authData;
    let offset = 0;
    offset += 32;
    const flags = authenticatorData[offset];
    offset += 1;
    const signCount = authenticatorData.slice(offset, offset + 4);
    offset += 4;
    const attestedCredentialDataIncluded = !!(flags & 0x40);
    if (!attestedCredentialDataIncluded) {
        throw new Error('Attested credential data not included');
    }
    const aaguid = authenticatorData.slice(offset, offset + 16);
    offset += 16;
    const credentialIdLength = authenticatorData.readUInt16BE(offset);
    offset += 2;
    const credentialId = authenticatorData.slice(offset, offset + credentialIdLength);
    offset += credentialIdLength;
    const publicKeyBytes = authenticatorData.slice(offset);
    const publicKeyCose = await Decoder.decodeFirst(publicKeyBytes);
    const publicKey = parseCOSEPublicKey(publicKeyCose);

    return {
        aaguid,
        signCount,
        credentialId,
        ...publicKey
    };
}

/**
 * Parses a COSE-encoded public key
 * @param {Object} cosePublicKey - The decoded COSE public key object
 * @returns {Buffer} - The parsed public key in a suitable format
 */
function parseCOSEPublicKey(cosePublicKey) {
    const kty = cosePublicKey.get(1); // Key Type
    const alg = cosePublicKey.get(3); // Algorithm

    if (kty === 2) { // EC2 key type (Elliptic Curve)
        const x = cosePublicKey.get(-2);
        const y = cosePublicKey.get(-3);
        return {
            kty,
            alg,
            x,
            y,
            publicKey: Buffer.concat([Buffer.from([0x04]), x, y])
        }
    }

    // Handle other key types (RSA, etc.) as needed
    throw new Error('Unsupported key type');
}

