# Giano Connector

A wagmi connector and RainbowKit wallet for Giano, with support for both web and Node.js environments.

## Installation

```bash
npm install @appliedblockchain/giano-connector
```

## Usage

### Web/React Environment

For web applications using wagmi and RainbowKit:

```typescript
import { createGianoConnector } from '@appliedblockchain/giano-connector';
// or specifically for web
import { createGianoConnector } from '@appliedblockchain/giano-connector/web';

const connector = createGianoConnector({
  provider: gianoProvider
});
```

### Node.js Environment

For Node.js applications without wagmi dependencies:

```typescript
import { GianoNodeConnector } from '@appliedblockchain/giano-connector/node';

const connector = new GianoNodeConnector({
  provider: gianoProvider
});

// Get accounts
const accounts = await connector.getAccounts();

// Get chain ID
const chainId = await connector.getChainId();

// Wait for user operation receipt
const receipt = await connector.waitForUserOperationReceipt(hash);

// Get smart account
const smartAccount = connector.getSmartAccount();
```

## API Reference

### Web Connector (`createGianoConnector`)

Creates a wagmi-compatible connector for web applications.

**Parameters:**
- `provider`: GianoProvider instance

**Returns:** A wagmi connector with standard wallet methods.

### Node Connector (`GianoNodeConnector`)

A class-based connector for Node.js environments.

**Constructor Parameters:**
- `config.provider`: GianoProvider instance

**Methods:**
- `getProvider()`: Returns the underlying provider
- `getChainId()`: Returns the current chain ID
- `getAccounts()`: Returns the current accounts
- `isAuthorized()`: Checks if the connector is authorized
- `waitForUserOperationReceipt(hash)`: Waits for a user operation receipt
- `sendTransaction(transaction)`: Sends a transaction
- `getSmartAccount()`: Returns the smart account instance
- `submitUserOperation(userOp)`: Submits a user operation (placeholder)

## Environment Compatibility

- **Web**: Full wagmi integration with RainbowKit support (default export)
- **Node.js**: Lightweight connector without wagmi dependencies (use `/node` export)
- **Backward Compatibility**: The main export still provides the web connector for existing code

## Building

```bash
npm run build
```

This will generate both ESM and CommonJS formats with TypeScript declarations. 
