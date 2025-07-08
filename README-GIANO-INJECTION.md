# Giano Provider Injection System

The Giano Provider Injection system is a flexible, extensible architecture that allows developers to customize how passkey credentials and associated data are stored and managed in Giano-powered applications. This system decouples storage logic from the core provider functionality, enabling different storage backends and custom business logic.

## Table of Contents

- [Overview](#overview)
- [Interface Specification](#interface-specification)
- [Storage Implementations](#storage-implementations)
- [Usage Examples](#usage-examples)
- [Custom Implementations](#custom-implementations)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)

## Overview

The injection system serves as a bridge between the Giano provider and your application's storage layer. It handles:

- **Credential Management**: Creating, retrieving, and validating WebAuthn credentials
- **Data Persistence**: Storing passkey IDs and public keys
- **User Identity**: Encoding/decoding user identifiers
- **Lifecycle Hooks**: Custom logic during credential creation and signing

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
  onUserOperationSigned?: (signedUserOp: any) => Promise<any>; // @deprecated
}
```

### Method Details

#### `getNameForCredential()`
Returns the display name for the credential during creation.

**Returns**: `string | Promise<string>`

#### `getCredentialInfo()`
Retrieves existing credential information or generates a new challenge.

**Returns**: `Promise<{ credentialId?: BufferSource | null; challenge: BufferSource }>`

- `credentialId`: Existing credential ID for sign-in, or `null` for new credential creation
- `challenge`: Random challenge bytes for the WebAuthn operation

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

const injection = createGianoServerInjection('user-123', 'https://api.example.com');
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
  injection: gianoInjection, // Demo app implementation
  // ... other config
});
```

### Example: Demo App Multi-User Server Storage

```typescript
// This is from the demo application - adapt to your needs
import { createGianoServerInjection } from './demo-server-injection';

function createUserProvider(userId: string) {
  const injection = createGianoServerInjection(userId); // Demo app implementation
  
  return createGianoProvider({
    injection,
    // ... other config
  });
}

// Different users get isolated storage
const aliceProvider = createUserProvider('alice-123');
const bobProvider = createUserProvider('bob-456');
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
  }>;
  setPasskeyId(id: string): Promise<void>;
  getPublicKey(rawId: ArrayBuffer): Promise<{ x: Hex; y: Hex } | null>;
  setPublicKey(rawId: ArrayBuffer, coords: { x: Hex; y: Hex }): Promise<void>;
  isAvailable(): boolean;
}
```

### Demo App Factory Functions

These functions are from the demo application and serve as reference implementations:

```typescript
// Demo app: Create injection with custom storage
function createGianoInjection(storage?: GianoStorage): GianoProviderInjection;

// Demo app: Create server-side storage injection
function createGianoServerInjection(userId: string, apiBaseUrl?: string): GianoProviderInjection;

// Demo app: Create storage with automatic fallback
function createGianoStorage(customStorage?: GianoStorage): GianoStorage;
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