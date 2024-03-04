<p align="center">
 <img src="assets/logo.png" width="200"/>
 <h1 align="center">Giano</h1>
</p>

This repository is a Proof of Concept showcasing how to use Passkey technology to authenticate users on a smart contract.

This repository is a demo showing how the user can authenticate on a smart contract using a Passkey.  
Relevant bits:
- [AuthClient.tsx](./src/client/components/AuthClient.tsx): the full logic running on client side.
- [Passkey.sol](./contracts/Passkey.sol): the smart contract method verifying the signature.

## Development

Install deps:
```sh
nvm install
yarn install
```

Start GETH node:
```sh
yarn hh:node
yarn hh:deploy --network localhost
```

Start application:
```sh
yarn build:dev
```

PoC available at <http://localhost:3000>.

Test contracts:
```sh
yarn hh:test
```
