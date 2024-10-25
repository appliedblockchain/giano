# @giano/rn-credential

The `@giano/rn-credential` follow common interface for handling credentials in multi-platform projects, you could use @giano/web-credential for web projects.

### Usage

To use the `@giano/rn-credential` package, you need to import and initialize the credential client in your React Native project. The client provides methods to create and retrieve credentials.

### Example

```ts
import { credentialClient } from '@giano/rn-credential';

const { createCredential, getCredential } = credentialClient({
    rp: {
       id: 'teamId.and.your.bundle.id',
       name: 'Giano',
    }
});

const id = 'username';
const challenge = 'challenge';

// Create a new credential
const newCredential = await createCredential(id, challenge);

// Get an existing credential
const existingCredential = await getCredential(id, challenge);
```

### Installation

To install the package, use the following command:

```sh
yarn add @giano/rn-credential
yarn add react-native-passkey
npx pod-install
```
