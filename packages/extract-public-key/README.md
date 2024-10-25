# @giano/extract-public-key

## Description

The `@giano/extract-public-key` package provides utilities to extract public keys from attestation objects, typically used in WebAuthn and other authentication protocols. This package is designed to parse and handle COSE-encoded public keys, making it easier to work with cryptographic data in JavaScript/TypeScript applications.

### Key Functionalities

1. **Extract Public Key**:
   - The primary functionality of this package is to extract the public key from a CBOR-encoded attestation object.
   - This is achieved using the [`extractPublicKey`](command:_github.copilot.openSymbolInFile?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2FUsers%2Fstevenkoch%2Fcodes%2Fgiano%2Fpackages%2Fextract-public-key%2Fsrc%2FextractPublicKey.ts%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22extractPublicKey%22%2C%22fbc1145a-740d-4f79-a803-2ce8e7927b7b%22%5D "/Users/stevenkoch/codes/giano/packages/extract-public-key/src/extractPublicKey.ts") function, which decodes the attestation object and parses the public key.

2. **Parse COSE Public Key**:
   - The package includes a helper function [`parseCOSEPublicKey`](command:_github.copilot.openSymbolInFile?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2FUsers%2Fstevenkoch%2Fcodes%2Fgiano%2Fpackages%2Fextract-public-key%2Fsrc%2FextractPublicKey.ts%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22parseCOSEPublicKey%22%2C%22fbc1145a-740d-4f79-a803-2ce8e7927b7b%22%5D "/Users/stevenkoch/codes/giano/packages/extract-public-key/src/extractPublicKey.ts") to parse COSE-encoded public keys.
   - This function supports EC2 (Elliptic Curve) key types and can be extended to handle other key types as needed.

3. **ASN.1 Parsing**:
   - The package provides utilities to parse ASN.1 encoded data, such as ECDSA public keys and signatures.
   - Functions like [`parsePublicKey`](command:_github.copilot.openSymbolInFile?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2FUsers%2Fstevenkoch%2Fcodes%2Fgiano%2Fpackages%2Fextract-public-key%2Fsrc%2Fmisc%2Fasn1%2Findex.ts%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22parsePublicKey%22%2C%22fbc1145a-740d-4f79-a803-2ce8e7927b7b%22%5D "/Users/stevenkoch/codes/giano/packages/extract-public-key/src/misc/asn1/index.ts") and [`parseSignature`](command:_github.copilot.openSymbolInFile?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2FUsers%2Fstevenkoch%2Fcodes%2Fgiano%2Fpackages%2Fextract-public-key%2Fsrc%2Fmisc%2Fasn1%2Findex.ts%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%2C%22parseSignature%22%2C%22fbc1145a-740d-4f79-a803-2ce8e7927b7b%22%5D "/Users/stevenkoch/codes/giano/packages/extract-public-key/src/misc/asn1/index.ts") handle the conversion and extraction of key components.

### Example Usage

```ts
import { extractPublicKey } from '@giano/extract-public-key';

const attestationObject = /* CBOR encoded attestation object */;
extractPublicKey(attestationObject).then(publicKey => {
    console.log('Extracted Public Key:', publicKey);
}).catch(error => {
    console.error('Error extracting public key:', error);
});
```

This package simplifies the process of working with public keys in authentication protocols, providing robust utilities for parsing and extracting key data.


### Installation

To install the `@giano/extract-public-key` package, you can use either npm or yarn. Follow the instructions below based on your package manager of choice.

#### Using npm

```sh
npm install @giano/extract-public-key
```

#### Using yarn

```sh
yarn add @giano/extract-public-key
```

This will add the `@giano/extract-public-key` package to your project's dependencies, allowing you to import and use its functionalities in your JavaScript/TypeScript applications.


### License

This package is licensed under the MIT License. You can find the full license text in the [LICENSE](LICENSE) file.
