# @giano/web-credential

The `@giano/web-credential` package provides a common interface for handling credentials in web projects using the WebAuthn API. This package allows you to create and retrieve credentials using passkeys.

## Usage

To use the `@giano/web-credential` package, you need to import and initialize the credential client in your web project. The client provides methods to create and retrieve credentials.

### Example

```ts
import { credentialClient } from '@giano/web-credential';
import {extractPublicKey} from '@giano/extract-public-key';

const { createCredential, getCredential } = credentialClient({
    rp: {
       id: window.location.hostname,
       name: 'Giano',
    }
});

const username = 'username';
const challenge = new TextEncoder().encode('challenge');

// Create a new credential
const newCredential = await createCredential(username, challenge);

const publicKey = await extractPublicKey(newCredential.response.attestationObject);

// Get an existing credential
const existingCredential = await getCredential(new TextEncoder().encode(username), challenge);
```

## Installation

To install the package, use the following command:

```sh
yarn add @giano/web-credential
```

## API

### `credentialClient`

Creates a credential client for the WebAuthn API.

#### Parameters

- `publicKey` (optional): Partial configuration for the `PublicKeyCredentialCreationOptions`.

#### Returns

An object with the following methods:

- `createCredential(username: string, challenge?: BufferSource): Promise<PublicKeyCredential & { response: AuthenticatorAttestationResponse }>`
- `getCredential(id?: BufferSource, challenge?: BufferSource): Promise<PublicKeyCredential & { response: AuthenticatorAssertionResponse }>`

## License

This project is licensed under the MIT License.


