<p align="center">
 <img src="assets/logo.png" width="200"/>
 <h1 align="center">Giano</h1>
</p>

The Giano project is a comprehensive suite of packages designed to streamline the onboarding process for Web3 technologies. It includes tools for handling credentials on both web and mobile platforms, extracting public keys, and managing smart wallets and account abstractions.

## Packages

### 1. @giano/web-credential

The [`@giano/web-credential`]("Go to definition") package provides a common interface for handling credentials in web projects using the WebAuthn API. This package allows you to create and retrieve credentials using passkeys.

#### Usage

```ts
import { credentialClient } from '@giano/web-credential';
import { extractPublicKey } from '@giano/extract-public-key';

const { createCredential, getCredential } = credentialClient({
    rp: {
       id: window.location.hostname,
       name

:

 'Giano',
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

#### Installation

```sh
yarn add @giano/web-credential
```

### 2. @giano/rn-credential

The [`@giano/rn-credential`]("Go to definition") package provides a common interface for handling credentials in multi-platform projects, specifically for React Native.

#### Usage

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

#### Installation

```sh
yarn add @giano/rn-credential
yarn add react-native-passkey
npx pod-install
```

### 3. @giano/extract-public-key

The [`@giano/extract-public-key`]("Go to definition") package provides utilities to parse ASN.1 encoded data, such as ECDSA public keys and signatures.

#### Usage

```ts
import { extractPublicKey } from '@giano/extract-public-key';

const attestationObject = /* CBOR encoded attestation object */;
extractPublicKey(attestationObject).then(publicKey => {
    console.log('Extracted Public Key:', publicKey);
}).catch(error => {
    console.error('Error extracting public key:', error);
});
```

#### Installation

```sh
npm install @giano/extract-public-key
```

### 4. Contracts

The [`contracts`]("Go to definition") package includes smart contracts that implement smart wallet and account abstraction mechanism.


#### Key Contracts

- Account.sol: A minimalist smart wallet implementation.
- AccountFactory.sol: A factory contract to deploy [`Account`]("Go to definition") contracts and map passkey IDs to [`Account`]("Go to definition") contract addresses.


#### Development

1. Install dependencies:

```sh
yarn install
```

2. Start Hardhat node and deploy contracts:

```sh
yarn hh:node
yarn hh:deploy --network localhost
```

3. Start application:

```sh
yarn web:build:dev
```

Application available at <http://localhost:3000>.

4. Test contracts:

```sh
yarn hh:test
```


### 5. Start React Native Example

To start the React Native example located in the mobile directory, follow these steps:

1. Navigate to the mobile

 directory:

```sh
cd services/mobile
```

2. Install dependencies:

```sh
yarn install
```

3. Link native dependencies:

```sh
npx pod-install
```

4. Start the Metro bundler:

```sh
yarn start
```

5. Run the application on an iOS simulator:

```sh
yarn ios
```

Ensure you have the necessary environment setup for React Native development on your machine. You can refer to the [React Native documentation](https://reactnative.dev/docs/environment-setup) for detailed instructions.





## License

This project is licensed under the MIT License. You can find the full license text in the 

LICENSE

 file.

## Contributing

We welcome contributions! Please read our CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

## Contact

For any questions or feedback, please open an issue on GitHub.

---

This README provides a quick overview of the Giano project and its packages, helping you get started with Web3 technologies efficiently.
