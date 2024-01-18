# Passkey PoC

This repository is a demo showing how the user can authenticate on a smart contract using a Passkey.

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
