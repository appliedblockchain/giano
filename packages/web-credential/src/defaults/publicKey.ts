const ES256 = -7;
const ES256K = -47;

export const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: new TextEncoder().encode('abc'),
    authenticatorSelection: {
        requireResidentKey: true,
        residentKey: 'required',
        userVerification: 'required',
    },
    rp: {
        id: 'localhost',
        name: 'Giano',
    },
    user: {
        id: new TextEncoder().encode('email'),
        displayName: 'email',
        name: 'email',
    },
    pubKeyCredParams: [
        {
            alg: ES256K,
            type: 'public-key',
        },
        {
            alg: ES256,
            type: 'public-key',
        },
    ],
    timeout: 60_000,
};
export const deepMerge = (target: any, source: any) => {
    for (const key in source) {
        if (source[key] instanceof Object)
            Object.assign(source[key], deepMerge(target[key], source[key]));
    }

    Object.assign(target || {}, source);
    return target;
}
