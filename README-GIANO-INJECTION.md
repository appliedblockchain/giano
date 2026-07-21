# Giano Provider Injection System

The Giano Provider Injection system is a flexible, extensible architecture that allows developers to customize how passkey credentials and associated data are stored and managed in Giano-powered applications. This system decouples storage logic from the core provider functionality, enabling different storage backends and custom business logic.

## Table of Contents

- [Recommended: the wallet-api reference injection](#recommended-the-wallet-api-reference-injection)
- [Overview](#overview)
- [Interface Specification](#interface-specification)
- [Storage Implementations](#storage-implementations)
- [Usage Examples](#usage-examples)
  - [Basic Usage with Custom Storage](#basic-usage-with-custom-storage)
  - [Demo App localStorage Usage](#example-demo-app-localstorage-usage)
  - [Configuring Backend Submission](#example-configuring-backend-submission)
  - [WebAuthn Configuration](#webauthn-configuration)
  - [Demo App Multi-User Server Storage](#example-demo-app-multi-user-server-storage)
  - [Accessing the Smart Account Instance](#accessing-the-smart-account-instance)
  - [Listening to Account Changes](#listening-to-account-changes)
  - [React Hook Example](#react-hook-example)
  - [Creating Your Own Storage Implementation](#creating-your-own-storage-implementation)
- [Custom Implementations](#custom-implementations)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)

## Recommended: the wallet-api reference injection

Since Phase 2 the default way to implement this seam is **`createWalletApiInjection`** from
`@appliedblockchain/giano-connector` — a complete, production-shaped implementation backed by the
`giano-wallet-api` service (Fastify + PostgreSQL): server-side WebAuthn verification via
@simplewebauthn, DB-backed credentials, opaque bearer sessions, and a policied ERC-4337
user-operation relay. The old demo Next.js storage API (`/api/storage/**`, `/api/submit-userop`)
has been deleted.

```typescript
import { createWalletApiInjection } from '@appliedblockchain/giano-connector';

const injection = createWalletApiInjection({
  apiUrl: 'https://wallet.example.com',       // giano-wallet-api base URL
  externalUserId: currentUser.id,             // your app's user id
  // production: your backend mints a grant for ceremony options (admin key server-to-server);
  // demos can run the wallet-api with OPEN_REGISTRATION=true instead
  getRegistrationGrant: () => myBackend.getGianoGrant(),
  onSessionChanged: (token) => token
    ? sessionStorage.setItem('giano-session', token)
    : sessionStorage.removeItem('giano-session'),
  sessionToken: sessionStorage.getItem('giano-session'),
});
```

Everything below documents the underlying interface — implement it yourself only if you cannot
run the wallet-api service. The localStorage injection in the demo app remains as the no-backend
variant for local experiments.

## Overview

The injection system serves as a bridge between the Giano provider and your application's storage layer. It handles:

- **Credential Management**: Creating, retrieving, and validating WebAuthn credentials
- **Data Persistence**: Storing passkey IDs and public keys
- **User Identity**: Encoding/decoding user identifiers
- **Lifecycle Hooks**: Custom logic during credential creation and signing
- **Transaction Submission**: Optional backend submission of user operations for validation and processing

### Key Benefits

- **Flexibility**: Create custom storage implementations that fit your application's architecture
- **Extensibility**: Add custom business logic at key points in the credential lifecycle
- **Scalability**: Support multi-user scenarios with isolated storage
- **Security**: Implement your own security measures and data validation

## Interface Specification

The core interface is `GianoProviderInjection` with the following methods:

### Required Methods

```typescript
interface GianoProviderInjection {
  // Credential Configuration
  getNameForCredential(): string | Promise<string>;
  getCredentialInfo(): Promise<{
    credentialId?: BufferSource | null;
    challenge: BufferSource;
  }>;

  // Credential Lifecycle
  onCredentialCreated(
    credentialName: string,
    challenge: BufferSource,
    credential: Omit<PublicKeyCredential, 'toJSON'>
  ): null | Promise<null> | Hex | Promise<Hex>;

  onCredentialSignedIn(credential: PublicKeyCredential): Promise<boolean>;

  // User Identity Management
  encodeUserId(
    id: string,
    gianoSmartWalletFactoryAddress: string,
    chainId: string,
    chainType: ChainType
  ): Uint8Array;

  decodeUserId(userId: Uint8Array): {
    userId: string;
    walletFactoryAddress: string;
    chainId: number;
    chainType: ChainType;
  };

  // Key Management
  getPublicKeyByCredentialId(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex }>;
  onCredentialKey(rawId: ArrayBuffer, xyVector: { x: Hex; y: Hex }): Promise<void>;

  // Optional Hooks
  /**
   * Override for sending user operations manually.
   * When provided, this function will handle the submission of signed user operations
   * instead of sending them directly to the bundler.
   *
   * @param signedUserOp - The complete signed user operation ready for submission
   * @returns Promise that resolves to the user operation hash
   */
  submitUserOperation?: (signedUserOp: UserOperation<GianoEntryPointVersion>) => Promise<Hash>;
}
```

### Method Details

#### `getNameForCredential()`
Returns the display name for the credential during creation.

**Returns**: `string | Promise<string>`

#### `getCredentialInfo()`
Retrieves existing credential information or generates a new challenge.

**Returns**: `Promise<{ credentialId?: BufferSource | null; challenge: BufferSource; showListCredential?: boolean }>`

- `credentialId`: Existing credential ID for sign-in, or `null` for new credential creation
- `challenge`: Random challenge bytes for the WebAuthn operation
- `showListCredential`: When `true`, shows a list of available credentials for user selection. When `false` or `undefined`, uses automatic credential selection from storage

#### `onCredentialCreated()`
Called after a new credential is successfully created.

**Parameters**:
- `credentialName`: Display name of the credential
- `challenge`: Challenge used in credential creation
- `credential`: The created WebAuthn credential

**Returns**: `null | Promise<null> | Hex | Promise<Hex>`
- Return `null` to proceed with standard smart wallet creation
- Return a wallet address to use an existing wallet instead

#### `onCredentialSignedIn()`
Validates and processes credential sign-in attempts.

**Parameters**:
- `credential`: The WebAuthn credential used for sign-in

**Returns**: `Promise<boolean>`
- Return `true` to allow sign-in
- Return `false` to reject sign-in

#### `encodeUserId()` / `decodeUserId()`
Handle user identity encoding for WebAuthn user IDs.

**encodeUserId Parameters**:
- `id`: Unique user identifier
- `gianoSmartWalletFactoryAddress`: Factory contract address
- `chainId`: Blockchain chain ID
- `chainType`: Chain type enumeration

**decodeUserId Parameters**:
- `userId`: Encoded user ID bytes

#### `getPublicKeyByCredentialId()` / `onCredentialKey()`
Manage public key storage and retrieval.

**getPublicKeyByCredentialId**: Retrieve stored public key coordinates
**onCredentialKey**: Store public key coordinates for a credential

#### `submitUserOperation()` (Optional)
Override for custom user operation submission.

This function is only included in the injection when `enableBackendSubmission` is set to `true` in the options. When present, it receives complete signed user operations and should handle their submission to your backend or bundler service, returning the user operation hash. The frontend can then use bundler/connector wait functions to wait for the receipt, giving developers full control over the waiting process.

### Transaction Flow with Backend Submission

When `submitUserOperation` is provided, the transaction flow works as follows:

1. **Preparation**: The provider prepares and signs the user operation
2. **Backend Submission**: The injection's `submitUserOperation` function submits the signed operation to your backend
3. **Immediate Response**: The backend returns the user operation hash immediately (no waiting)
4. **Frontend Waiting**: The frontend uses bundler/connector methods like `waitForUserOperationReceipt(hash)` to wait for the receipt

**Benefits of Hash-Only Response**:
- **Better Performance**: Backend responds immediately instead of waiting for confirmation
- **More Control**: Developers can implement custom waiting logic, timeouts, and error handling
- **Scalability**: Backend doesn't hold connections open for long periods
- **Flexibility**: Frontend can show progress indicators, implement retries, or handle timeouts differently

**Example Flow**:
```typescript
// Frontend transaction call
const hash = await writeContractAsync({
  address: tokenAddress,
  abi: tokenAbi,
  functionName: 'transfer',
  args: [recipient, amount],
});

// Frontend handles waiting with full control
const receipt = await gianoConnector.waitForUserOperationReceipt(hash);
```

## Storage Implementations

**Important**: Storage implementations are **application-specific** and must be created by developers based on their specific requirements. Giano provides the injection interface but does not include any built-in storage implementations.

The examples below are from the demo application and serve as reference implementations. You should create your own storage layer that fits your application's architecture, security requirements, and data persistence needs.

### Example 1: localStorage Implementation (Demo App)

This is a reference implementation from the demo application that uses browser localStorage with automatic fallback to in-memory storage.

```typescript
// This is an example implementation from the demo app
import { gianoInjection } from './giano-injection';

const provider = createGianoProvider({
  injection: gianoInjection,
  // ... other config
});
```

**Example Storage Keys Used**:
- `gpk-passkey-id`: Base64-encoded passkey ID
- `gpk-{credentialIdHex}-public-key`: Public key X coordinate
- `gpk-{credentialIdHex}-public-key-y`: Public key Y coordinate

### Example 2: In-Memory Storage (Demo App)

This demo implementation stores data in memory (lost on page reload). Useful for testing or temporary sessions.

```typescript
// This is an example implementation from the demo app
import { gianoMemoryInjection } from './giano-injection';

const provider = createGianoProvider({
  injection: gianoMemoryInjection,
  // ... other config
});
```

### Example 3: Server-Side Storage (Demo App)

This demo implementation stores data on your server with RESTful API endpoints.

```typescript
// This is an example implementation from the demo app
import { createGianoServerInjection } from './demo-server-injection';

const injection = createGianoServerInjection('user-123', {
  apiBaseUrl: 'https://api.example.com',
  enableBackendSubmission: true
});
const provider = createGianoProvider({
  injection,
  // ... other config
});
```

**Example API Endpoints**:
- `GET /api/storage/users/{userId}/credential-info` - Get unified credential info (passkeyId + server-generated challenge)
- `GET /api/storage/users/{userId}/passkeys` - Get passkey data
- `PUT /api/storage/users/{userId}/passkeys` - Update passkey data
- `GET /api/storage/users/{userId}/public-keys/{idHash}` - Get public key
- `PUT /api/storage/users/{userId}/public-keys/{idHash}` - Store public key

#### New Unified Credential Info Endpoint

The `GET /api/storage/users/{userId}/credential-info` endpoint is the key improvement for server-side storage. It returns both the passkey ID and a server-generated challenge in a single atomic operation:

```json
{
  "passkeyId": "base64-encoded-passkey-id-or-null",
  "challenge": [1, 2, 3, ...] // Array of 32 bytes for the challenge
}
```

**Security Benefits**:
- **Server-side challenge generation**: Ensures challenges are cryptographically secure and can be validated server-side
- **Atomic operation**: Both credential ID and challenge are retrieved together, preventing race conditions
- **Centralized validation**: Server can implement additional security measures like rate limiting, challenge expiration, etc.

**Implementation Notes**:
- The challenge is a 32-byte array generated using `crypto.getRandomValues()`
- The passkeyId is base64-encoded for JSON transport
- Returns `null` for passkeyId when no credential exists for the user

### Security Improvements

1. **Server-Generated Challenge**: The challenge is now generated server-side for the server storage implementation, allowing for better validation and security measures.

2. **Unified Retrieval**: Both credential ID and challenge are retrieved in a single atomic operation from the server.

3. **Fallback Safety**: If the server fails, the system falls back to local challenge generation to maintain functionality.

4. **Atomic Operations**: The new `getCredentialInfo()` method ensures both passkeyId and challenge are retrieved atomically, preventing race conditions and improving consistency.

## Usage Examples

### Basic Usage with Custom Storage

```typescript
import { createGianoProvider } from '@appliedblockchain/giano-connector';

// Create your own injection implementation
const myCustomInjection: GianoProviderInjection = {
  // ... implement all required methods based on your needs
};

const { gianoProvider } = createGianoProvider({
  injection: myCustomInjection,
  bundler: myBundler,
  chains: [hardhat],
  transports: { [hardhat.id]: http() },
  initialChainId: hardhat.id,
  gianoSmartWalletFactoryAddress: '0x...',
});
```

### Example: Demo App localStorage Usage

```typescript
// This is from the demo application - adapt to your needs
import { gianoInjection } from './giano-injection';

const { gianoProvider } = createGianoProvider({
  injection: gianoInjection, // Demo app implementation with backend submission enabled
  // ... other config
});
```

### Example: Configuring Backend Submission

You can control whether user operations are submitted through your backend or directly to the bundler:

```typescript
// Enable backend submission (default for demo app)
const injectionWithBackend = createGianoInjection({ 
  enableBackendSubmission: true 
});

// Disable backend submission - use direct bundler submission
const injectionDirectSubmission = createGianoInjection({ 
  enableBackendSubmission: false 
});

// Custom storage with backend submission
const injectionCustomStorage = createGianoInjection({
  storage: new MyCustomStorage(),
  enableBackendSubmission: true
});
```

### WebAuthn Configuration

The Giano provider supports configurable WebAuthn parameters that ensure consistency between credential creation and retrieval operations. These parameters are applied uniformly across all WebAuthn operations.

#### Configurable Parameters

```typescript
interface CreateGianoProviderParams {
  // ... existing params
  userVerification?: 'required' | 'preferred' | 'discouraged';
  mediation?: 'silent' | 'optional' | 'required';
}
```

#### User Verification Options

The `userVerification` parameter controls the user verification requirement for WebAuthn operations:

- **`'required'`** (default): User verification is mandatory for all operations
- **`'preferred'`**: User verification is preferred but not mandatory
- **`'discouraged'`**: User verification is discouraged, allowing faster operations

```typescript
// High security - require user verification
const secureProvider = createGianoProvider({
  injection: myInjection,
  userVerification: 'required',
  // ... other config
});

// Balanced security - prefer user verification
const balancedProvider = createGianoProvider({
  injection: myInjection,
  userVerification: 'preferred',
  // ... other config
});

// Fast operations - discourage user verification
const fastProvider = createGianoProvider({
  injection: myInjection,
  userVerification: 'discouraged',
  // ... other config
});
```

#### Mediation Options

The `mediation` parameter controls credential mediation behavior:

- **`'silent'`** (default): Silent credential retrieval without user interaction
- **`'optional'`**: Optional mediation with user interaction when needed
- **`'required'`**: Required mediation with explicit user selection

```typescript
// Silent credential selection (default)
const silentProvider = createGianoProvider({
  injection: myInjection,
  mediation: 'silent',
  // ... other config
});

// Optional user interaction
const optionalProvider = createGianoProvider({
  injection: myInjection,
  mediation: 'optional',
  // ... other config
});

// Always require user selection
const requiredProvider = createGianoProvider({
  injection: myInjection,
  mediation: 'required',
  // ... other config
});
```

#### Enhanced Credential Selection

The `getCredentialInfo()` method now supports an optional `showListCredential` parameter that allows for enhanced credential selection:

```typescript
const enhancedInjection: GianoProviderInjection = {
  getCredentialInfo: async () => {
    const existingCredential = await getStoredCredential();
    
    return {
      credentialId: existingCredential?.id || null,
      challenge: generateChallenge(),
      showListCredential: true // Show credential selection UI
    };
  },
  // ... other methods
};
```

**Credential Selection Behavior**:
- **`showListCredential: true`**: Displays a list of available credentials for user selection
- **`showListCredential: false` or `undefined`**: Uses automatic credential selection from storage

#### Consistent Parameter Application

All WebAuthn parameters are applied consistently across credential operations:

```typescript
// These parameters apply to both create and get operations
const consistentProvider = createGianoProvider({
  injection: myInjection,
  userVerification: 'required',
  mediation: 'silent',
  // ... other config
});

// The same userVerification and mediation settings will be used for:
// 1. navigator.credentials.create() - when creating new credentials
// 2. navigator.credentials.get() - when retrieving existing credentials
```

#### Security Considerations

When configuring WebAuthn parameters, consider your application's security requirements:

- **High Security Applications**: Use `userVerification: 'required'` for maximum security
- **User Experience Focused**: Use `userVerification: 'preferred'` for balanced security and UX
- **Performance Critical**: Use `userVerification: 'discouraged'` for fastest operations
- **Multi-Credential Support**: Use `mediation: 'required'` when users have multiple credentials

### Example: Demo App Multi-User Server Storage

```typescript
// This is from the demo application - adapt to your needs
import { createGianoServerInjection } from './demo-server-injection';

function createUserProvider(userId: string, options = {}) {
  const injection = createGianoServerInjection(userId, options); // Demo app implementation
  
  return createGianoProvider({
    injection,
    // ... other config
  });
}

// Different users get isolated storage with backend submission
const aliceProvider = createUserProvider('alice-123', { enableBackendSubmission: true });
const bobProvider = createUserProvider('bob-456', { enableBackendSubmission: false }); // Direct bundler submission
```

### Accessing the Smart Account Instance

You can access the current smart account instance using the `getSmartAccount()` method on the provider:

```typescript
import { createGianoProvider } from '@appliedblockchain/giano-connector';

const { gianoProvider } = createGianoProvider({
  injection: myCustomInjection,
  // ... other config
});

// Check if a smart account is connected
const smartAccount = gianoProvider.getSmartAccount();
if (smartAccount) {
  const address = await smartAccount.getAddress();
  console.log('Connected smart account address:', address);
  
  // Access smart account methods
  const signature = await smartAccount.signMessage({ 
    message: 'Hello, Giano!' 
  });
  
  // Sign user operations
  const userOpSignature = await smartAccount.signUserOperation({
    sender: address,
    nonce: 0n,
    initCode: '0x',
    callData: '0x',
    callGasLimit: 0n,
    verificationGasLimit: 0n,
    preVerificationGas: 0n,
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
    paymasterAndData: '0x',
    signature: '0x'
  });
} else {
  console.log('No smart account connected');
}
```

#### Listening to Account Changes

You can listen to the `accountChanged` event to react to smart account connection changes:

```typescript
// Listen for account changes
gianoProvider.on('accountChanged', (accounts: string[]) => {
  const smartAccount = gianoProvider.getSmartAccount();
  
  if (accounts.length === 0) {
    console.log('User disconnected - no smart account available');
    // Handle disconnection
  } else {
    console.log('Account changed to:', accounts[0]);
    
    if (smartAccount) {
      // Smart account is connected and ready to use
      smartAccount.getAddress().then(address => {
        console.log('Connected smart account address:', address);
      });
    } else {
      console.log('Smart account not yet available');
    }
  }
});

// Example: Check smart account status in event handlers
gianoProvider.on('connect', (connectInfo) => {
  console.log('Provider connected:', connectInfo);
  
  const smartAccount = gianoProvider.getSmartAccount();
  if (smartAccount) {
    console.log('Smart account is available after connection');
  }
});

gianoProvider.on('disconnect', (error) => {
  console.log('Provider disconnected:', error);
  
  const smartAccount = gianoProvider.getSmartAccount();
  if (!smartAccount) {
    console.log('Smart account is no longer available');
  }
});
```

### Listening to Account Changes

The Giano provider emits standard EIP-1193 events, including `accountsChanged`. You can listen to these events to react to account state changes. For detailed examples of listening to account changes and accessing the smart account instance, see the [Accessing the Smart Account Instance](#accessing-the-smart-account-instance) section above.

```typescript
import { createGianoProvider } from '@appliedblockchain/giano-connector';

const { gianoProvider } = createGianoProvider({
  injection: myCustomInjection,
  // ... other config
});

// Listen for account changes
gianoProvider.on('accountsChanged', (accounts: string[]) => {
  if (accounts.length === 0) {
    console.log('User disconnected or no accounts available');
    // Handle disconnection
  } else {
    console.log('Account changed to:', accounts[0]);
    // Handle new account connection
  }
});

// Listen for chain changes
gianoProvider.on('chainChanged', (chainId: string) => {
  console.log('Chain changed to:', chainId);
  // Handle chain change
});

// Listen for disconnection
gianoProvider.on('disconnect', (error) => {
  console.log('Provider disconnected:', error);
  // Handle disconnection
});

// Listen for connection
gianoProvider.on('connect', (connectInfo) => {
  console.log('Provider connected:', connectInfo);
  // Handle connection
});
```

### Creating Your Own Storage Implementation

```typescript
// This is what you should implement in your application
class MyCustomStorage implements GianoStorage {
  constructor(private userId: string) {}

  async getCredentialInfo(): Promise<{
    passkeyId: string | null;
    challenge: Uint8Array;
  }> {
    // Implement your unified credential info retrieval logic
    // Could be: database, API call, file system, etc.
    const passkeyId = await this.retrievePasskeyId(this.userId);
    const challenge = await this.generateChallenge();
    return { passkeyId, challenge };
  }

  async setPasskeyId(id: string): Promise<void> {
    // Implement your storage persistence logic
    await this.persistPasskeyId(this.userId, id);
  }

  async getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null> {
    // Implement your public key retrieval logic
    const credentialId = Buffer.from(rawId).toString('hex');
    return await this.retrievePublicKey(this.userId, credentialId);
  }

  async setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void> {
    // Implement your public key storage logic
    const credentialId = Buffer.from(rawId).toString('hex');
    await this.persistPublicKey(this.userId, credentialId, coords);
  }

  isAvailable(): boolean {
    // Check if your storage system is available
    return this.storageSystemIsReady();
  }

  // Your custom storage methods
  private async retrievePasskeyId(userId: string): Promise<string | null> {
    // Implement based on your storage system
  }

  private async persistPasskeyId(userId: string, passkeyId: string): Promise<void> {
    // Implement based on your storage system
  }

  private async generateChallenge(): Promise<Uint8Array> {
    // Generate secure challenge - could be server-side or client-side
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    return challenge;
  }

  private async retrievePublicKey(userId: string, credentialId: string): Promise<{ x: Hex; y: Hex } | null> {
    // Implement based on your storage system
  }

  private async persistPublicKey(userId: string, credentialId: string, coords: { x: Hex; y: Hex }): Promise<void> {
    // Implement based on your storage system
  }

  private storageSystemIsReady(): boolean {
    // Check your storage system availability
    return true;
  }
}

// Create your injection using your custom storage
const myInjection: GianoProviderInjection = {
  // ... implement all required methods using your MyCustomStorage
};
```

## Custom Implementations

### Creating Custom Injections

**This is the expected approach for production applications.** You should create custom injections by implementing the `GianoProviderInjection` interface based on your specific requirements:

```typescript
const customInjection: GianoProviderInjection = {
  getNameForCredential: async () => 'My Custom Passkey',

  getCredentialInfo: async () => {
    // Custom credential retrieval logic
    const existingId = await getStoredCredentialId();
    return {
      credentialId: existingId,
      challenge: generateCustomChallenge(),
    };
  },

  onCredentialCreated: async (name, challenge, credential) => {
    // Custom post-creation logic
    await logCredentialCreation(credential);
    await storeCredentialMetadata(credential);
    return null; // Proceed with standard flow
  },

  onCredentialSignedIn: async (credential) => {
    // Custom authentication logic
    const isValid = await validateCredential(credential);
    if (isValid) {
      await logSignIn(credential);
      return true;
    }
    return false;
  },

  // ... implement other required methods

  // Optional: Custom backend submission
  submitUserOperation: async (signedUserOp) => {
    // Submit to your backend for validation and bundler submission
    const response = await fetch('/api/submit-userop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedUserOp),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(`Backend submission failed: ${errorData.error}`);
    }

    const result = await response.json();

    // Return just the user operation hash - frontend handles waiting
    return result.hash;
  },
};
```

### Adding Business Logic

Use lifecycle hooks to add custom business logic:

```typescript
const businessLogicInjection: GianoProviderInjection = {
  // ... standard implementations

  onCredentialCreated: async (name, challenge, credential) => {
    // Business logic: Create user profile
    await createUserProfile(credential.id);

    // Business logic: Send welcome email
    await sendWelcomeEmail(credential.id);

    // Business logic: Initialize user preferences
    await initializeUserPreferences(credential.id);

    return null;
  },

  onCredentialSignedIn: async (credential) => {
    // Business logic: Check user permissions
    const permissions = await getUserPermissions(credential.id);
    if (!permissions.canSignIn) {
      return false;
    }

    // Business logic: Update last login
    await updateLastLogin(credential.id);

    // Business logic: Check for security alerts
    await checkSecurityAlerts(credential.id);

    return true;
  },
};
```

## Best Practices

### Security Considerations

1. **Validate Input**: Always validate credential data before processing
2. **Secure Storage**: Use encrypted storage for sensitive data
3. **Rate Limiting**: Implement rate limiting for credential operations
4. **Audit Logging**: Log security-relevant events

```typescript
const secureInjection: GianoProviderInjection = {
  onCredentialSignedIn: async (credential) => {
    // Validate credential format
    if (!isValidCredential(credential)) {
      await logSecurityEvent('Invalid credential format', credential.id);
      return false;
    }

    // Check rate limiting
    if (await isRateLimited(credential.id)) {
      await logSecurityEvent('Rate limit exceeded', credential.id);
      return false;
    }

    // Audit log
    await logSecurityEvent('Successful sign-in', credential.id);
    return true;
  },
};
```

### Transaction Handling

When implementing `submitUserOperation`, follow these patterns for optimal user experience:

```typescript
const userControlledInjection: GianoProviderInjection = {
  // ... other methods

  submitUserOperation: async (signedUserOp) => {
    try {
      // Submit to backend - returns hash immediately
      const response = await fetch('/api/submit-userop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signedUserOp),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`Backend submission failed: ${errorData.error}`);
      }

      const result = await response.json();

      // Return user operation hash immediately - let frontend control waiting
      return result.hash;
    } catch (error) {
      console.error('Transaction submission failed:', error);
      throw error;
    }
  },
};
```

**Frontend Waiting Patterns**:

```typescript
// Basic waiting with default timeout
const hash = await writeContractAsync({...});
const receipt = await gianoConnector.waitForUserOperationReceipt(hash);

// Custom timeout handling
const hash = await writeContractAsync({...});
const receipt = await Promise.race([
  gianoConnector.waitForUserOperationReceipt(hash),
  new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Transaction timeout')), 60000)
  )
]);

// Progress indication
const hash = await writeContractAsync({...});
const progressInterval = setInterval(() => {
  console.log('Waiting for transaction confirmation...');
}, 1000);

try {
  const receipt = await gianoConnector.waitForUserOperationReceipt(hash);
  console.log('Transaction confirmed!', receipt);
} finally {
  clearInterval(progressInterval);
}
```

### Error Handling

Implement robust error handling in your injection methods:

```typescript
const robustInjection: GianoProviderInjection = {
  getPublicKeyByCredentialId: async (rawId: ArrayBuffer) => {
    try {
      const publicKey = await storage.getPublicKey(rawId);
      if (!publicKey) {
        throw new Error('Public key not found');
      }
      return publicKey;
    } catch (error) {
      console.error('Failed to retrieve public key:', error);
      // Implement fallback logic or re-throw
      throw new Error('Public key retrieval failed');
    }
  },
};
```

### Testing

Create test implementations for development and testing:

```typescript
const testInjection: GianoProviderInjection = {
  getNameForCredential: async () => 'Test Passkey',

  getCredentialInfo: async () => ({
    credentialId: null, // Always create new credentials in tests
    challenge: new Uint8Array(32), // Fixed challenge for predictable tests
  }),

  onCredentialCreated: async () => {
    console.log('Test: Credential created');
    return null;
  },

  // Test implementation for backend submission
  submitUserOperation: async (signedUserOp) => {
    console.log('Test: Submitting user operation', signedUserOp);
    // Return a mock hash for testing
    return '0x1234567890abcdef1234567890abcdef12345678';
  },

  // ... other test implementations
};
```

## API Reference

### Types

```typescript
enum ChainType {
  HARDHAT = 0,
}

interface GianoStorage {
  getCredentialInfo(): Promise<{
    passkeyId: string | null;
    challenge: Uint8Array;
    showListCredential?: boolean;
  }>;
  setPasskeyId(id: string): Promise<void>;
  getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null>;
  setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void>;
  isAvailable(): boolean;
}

// WebAuthn Configuration Types
interface CreateGianoProviderParams {
  // ... existing params
  userVerification?: 'required' | 'preferred' | 'discouraged';
  mediation?: 'silent' | 'optional' | 'required';
}
```

### Demo App Factory Functions

These functions are from the demo application and serve as reference implementations:

```typescript
// Demo app: Options for creating Giano injection
interface CreateGianoInjectionOptions {
  storage?: GianoStorage;
  enableBackendSubmission?: boolean;
}

// Demo app: Create injection with custom storage and options
function createGianoInjection(options?: CreateGianoInjectionOptions): GianoProviderInjection;

// Demo app: Options for server injection
interface CreateGianoServerInjectionOptions {
  apiBaseUrl?: string;
  enableBackendSubmission?: boolean;
}

// Demo app: Create server-side storage injection
function createGianoServerInjection(
  userId: string, 
  options?: CreateGianoServerInjectionOptions
): GianoProviderInjection;

// Demo app: Create storage with automatic fallback
function createGianoStorage(customStorage?: GianoStorage): GianoStorage;
```

### Smart Account API

The `getSmartAccount()` method provides access to the current connected smart account and its methods:

```typescript
// Smart Account Methods
interface SmartAccount<GianoSmartAccountImplementation> {
  // Get the smart account address
  getAddress(): Promise<Address>;
  
  // Sign a message
  signMessage(parameters: { message: Hex | string }): Promise<Hex>;
  
  // Sign typed data (EIP-712)
  signTypedData(parameters: TypedDataDefinition): Promise<Hex>;
  
  // Sign a user operation
  signUserOperation(parameters: UserOperation): Promise<Hex>;
  
  // Sign static call permission
  signStaticCallPermission(): Promise<{ signature: Hex; signedAt: number }>;
  
  // Decode call data
  decodeCalls(data: Hex): Promise<Call[]>;
  
  // Encode calls to smart account format
  encodeCalls(calls: Call[]): Promise<Hex>;
  
  // Get factory arguments for account creation
  getFactoryArgs(): Promise<{ factory: Address; factoryData: Hex }>;
  
  // Get stub signature for gas estimation
  getStubSignature(): Promise<Hex>;
}


provider.on('accountsChanged', () => {
  const smartAccount = provider.getSmartAccount();
  if (smartAccount) {
    const address = await smartAccount.getAddress();
    console.log('Smart account address:', address);
  }
})
```

#### Creating a useSmartAccount hook (React)

This hook is used to get the smart account instance in a React component.

```typescript
import { useSyncExternalStore } from 'react';

const subscribe = (callback) => {
  provider.on('accountChanged', callback);
  return () => provider.off('accountChanged', callback);
};
const getSnapshot = () => provider.getSmartAccount();

export const useSmartAccount = () => {
  return useSyncExternalStore(subscribe, getSnapshot);
};
```

### Provider Events

The Giano provider implements the standard EIP-1193 event interface:

```typescript
interface GianoProvider {
  // Request methods
  request(args: EIP1193Parameters): Promise<any>;
  
  // Event listeners
  on<E extends keyof EIP1193EventMap>(event: E, listener: EventHandler<E>): GianoProvider;
  removeListener<E extends keyof EIP1193EventMap>(event: E, listener: EventHandler<E>): GianoProvider;
}

// Available events
interface EIP1193EventMap {
  accountsChanged: [accounts: string[]];
  chainChanged: [chainId: string];
  connect: [connectInfo: { chainId: string }];
  disconnect: [error: { code: number; name: string; message: string; details?: string }];
}
```

### Demo App Example Injections

These are example injections from the demo application:

```typescript
// Demo app: localStorage injection with fallback
export const gianoInjection: GianoProviderInjection;

// Demo app: In-memory only injection
export const gianoMemoryInjection: GianoProviderInjection;
```

---

This injection system provides the flexibility to adapt Giano to your specific application needs while maintaining security and usability. You should implement your own custom storage and injection logic based on your application's requirements. The examples shown are from the demo application and serve as reference implementations to help you understand the patterns and build your own solutions.
