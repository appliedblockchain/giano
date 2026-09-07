//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AccessControlEnumerableUpgradeable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const accessControlEnumerableUpgradeableAbi = [
  { type: 'error', inputs: [], name: 'AccessControlBadConfirmation' },
  {
    type: 'error',
    inputs: [
      { name: 'account', internalType: 'address', type: 'address' },
      { name: 'neededRole', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'AccessControlUnauthorizedAccount',
  },
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'previousAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'newAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
    ],
    name: 'RoleAdminChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleGranted',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleRevoked',
  },
  { type: 'function', inputs: [], name: 'DEFAULT_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleAdmin',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'index', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'getRoleMember',
    outputs: [{ name: '', internalType: 'address', type: 'address' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleMemberCount',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleMembers',
    outputs: [{ name: '', internalType: 'address[]', type: 'address[]' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'grantRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'hasRole',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'callerConfirmation', internalType: 'address', type: 'address' },
    ],
    name: 'renounceRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'revokeRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'interfaceId', internalType: 'bytes4', type: 'bytes4' }],
    name: 'supportsInterface',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AccessControlUpgradeable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const accessControlUpgradeableAbi = [
  { type: 'error', inputs: [], name: 'AccessControlBadConfirmation' },
  {
    type: 'error',
    inputs: [
      { name: 'account', internalType: 'address', type: 'address' },
      { name: 'neededRole', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'AccessControlUnauthorizedAccount',
  },
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'previousAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'newAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
    ],
    name: 'RoleAdminChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleGranted',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleRevoked',
  },
  { type: 'function', inputs: [], name: 'DEFAULT_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleAdmin',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'grantRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'hasRole',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'callerConfirmation', internalType: 'address', type: 'address' },
    ],
    name: 'renounceRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'revokeRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'interfaceId', internalType: 'bytes4', type: 'bytes4' }],
    name: 'supportsInterface',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Address
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const addressAbi = [{ type: 'error', inputs: [{ name: 'target', internalType: 'address', type: 'address' }], name: 'AddressEmptyCode' }] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// AuthenticatedStaticCaller
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const authenticatedStaticCallerAbi = [
  { type: 'error', inputs: [], name: 'InvalidSignature' },
  {
    type: 'error',
    inputs: [
      { name: 'expiredAt', internalType: 'uint256', type: 'uint256' },
      { name: 'currentTimestamp', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'SignatureExpired',
  },
  { type: 'function', inputs: [], name: 'domainSeparator', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [],
    name: 'eip712Domain',
    outputs: [
      { name: 'fields', internalType: 'bytes1', type: 'bytes1' },
      { name: 'name', internalType: 'string', type: 'string' },
      { name: 'version', internalType: 'string', type: 'string' },
      { name: 'chainId', internalType: 'uint256', type: 'uint256' },
      { name: 'verifyingContract', internalType: 'address', type: 'address' },
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'extensions', internalType: 'uint256[]', type: 'uint256[]' },
    ],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'getSignatureLifetime', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'hash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'signature', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'isValidSignature',
    outputs: [{ name: 'result', internalType: 'bytes4', type: 'bytes4' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'hash', internalType: 'bytes32', type: 'bytes32' }],
    name: 'replaySafeHash',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'call',
        internalType: 'struct StaticCall',
        type: 'tuple',
        components: [
          { name: 'target', internalType: 'address', type: 'address' },
          { name: 'data', internalType: 'bytes', type: 'bytes' },
          { name: 'signedAt', internalType: 'uint256', type: 'uint256' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
    ],
    name: 'signedStaticCall',
    outputs: [{ name: '', internalType: 'bytes', type: 'bytes' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BasePaymaster
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const basePaymasterAbi = [
  { type: 'error', inputs: [{ name: 'owner', internalType: 'address', type: 'address' }], name: 'OwnableInvalidOwner' },
  { type: 'error', inputs: [{ name: 'account', internalType: 'address', type: 'address' }], name: 'OwnableUnauthorizedAccount' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'previousOwner', internalType: 'address', type: 'address', indexed: true },
      { name: 'newOwner', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'OwnershipTransferred',
  },
  {
    type: 'function',
    inputs: [{ name: 'unstakeDelaySec', internalType: 'uint32', type: 'uint32' }],
    name: 'addStake',
    outputs: [],
    stateMutability: 'payable',
  },
  { type: 'function', inputs: [], name: 'deposit', outputs: [], stateMutability: 'payable' },
  { type: 'function', inputs: [], name: 'entryPoint', outputs: [{ name: '', internalType: 'contract IEntryPoint', type: 'address' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'getDeposit', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'owner', outputs: [{ name: '', internalType: 'address', type: 'address' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'mode', internalType: 'enum IPaymaster.PostOpMode', type: 'uint8' },
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'actualGasCost', internalType: 'uint256', type: 'uint256' },
      { name: 'actualUserOpFeePerGas', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'postOp',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [], name: 'renounceOwnership', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [{ name: 'newOwner', internalType: 'address', type: 'address' }],
    name: 'transferOwnership',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [], name: 'unlockStake', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'maxCost', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'validatePaymasterUserOp',
    outputs: [
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'validationData', internalType: 'uint256', type: 'uint256' },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'withdrawAddress', internalType: 'address payable', type: 'address' }],
    name: 'withdrawStake',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'withdrawAddress', internalType: 'address payable', type: 'address' },
      { name: 'amount', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'withdrawTo',
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CallContextChecker
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const callContextCheckerAbi = [{ type: 'error', inputs: [], name: 'UnauthorizedCallContext' }] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ContextUpgradeable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const contextUpgradeableAbi = [
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Create2
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const create2Abi = [{ type: 'error', inputs: [], name: 'Create2EmptyBytecode' }] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ECDSA
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ecdsaAbi = [
  { type: 'error', inputs: [], name: 'ECDSAInvalidSignature' },
  { type: 'error', inputs: [{ name: 'length', internalType: 'uint256', type: 'uint256' }], name: 'ECDSAInvalidSignatureLength' },
  { type: 'error', inputs: [{ name: 's', internalType: 'bytes32', type: 'bytes32' }], name: 'ECDSAInvalidSignatureS' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// EIP712Upgradeable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const eip712UpgradeableAbi = [
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  { type: 'event', anonymous: false, inputs: [], name: 'EIP712DomainChanged' },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
  {
    type: 'function',
    inputs: [],
    name: 'eip712Domain',
    outputs: [
      { name: 'fields', internalType: 'bytes1', type: 'bytes1' },
      { name: 'name', internalType: 'string', type: 'string' },
      { name: 'version', internalType: 'string', type: 'string' },
      { name: 'chainId', internalType: 'uint256', type: 'uint256' },
      { name: 'verifyingContract', internalType: 'address', type: 'address' },
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'extensions', internalType: 'uint256[]', type: 'uint256[]' },
    ],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ERC1271
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const erc1271Abi = [
  { type: 'function', inputs: [], name: 'domainSeparator', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [],
    name: 'eip712Domain',
    outputs: [
      { name: 'fields', internalType: 'bytes1', type: 'bytes1' },
      { name: 'name', internalType: 'string', type: 'string' },
      { name: 'version', internalType: 'string', type: 'string' },
      { name: 'chainId', internalType: 'uint256', type: 'uint256' },
      { name: 'verifyingContract', internalType: 'address', type: 'address' },
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'extensions', internalType: 'uint256[]', type: 'uint256[]' },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'hash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'signature', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'isValidSignature',
    outputs: [{ name: 'result', internalType: 'bytes4', type: 'bytes4' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'hash', internalType: 'bytes32', type: 'bytes32' }],
    name: 'replaySafeHash',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ERC1271InputGenerator
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const erc1271InputGeneratorAbi = [
  {
    type: 'constructor',
    inputs: [
      { name: 'account', internalType: 'contract GianoSmartWallet', type: 'address' },
      { name: 'hash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'accountFactory', internalType: 'address', type: 'address' },
      { name: 'factoryCalldata', internalType: 'bytes', type: 'bytes' },
    ],
    stateMutability: 'nonpayable',
  },
  { type: 'error', inputs: [], name: 'AccountDeploymentFailed' },
  {
    type: 'error',
    inputs: [
      { name: 'account', internalType: 'address', type: 'address' },
      { name: 'returned', internalType: 'address', type: 'address' },
    ],
    name: 'ReturnedAddressDoesNotMatchAccount',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ERC165Upgradeable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const erc165UpgradeableAbi = [
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
  {
    type: 'function',
    inputs: [{ name: 'interfaceId', internalType: 'bytes4', type: 'bytes4' }],
    name: 'supportsInterface',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ERC1967Proxy
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const erc1967ProxyAbi = [
  {
    type: 'constructor',
    inputs: [
      { name: 'implementation', internalType: 'address', type: 'address' },
      { name: '_data', internalType: 'bytes', type: 'bytes' },
    ],
    stateMutability: 'payable',
  },
  { type: 'error', inputs: [{ name: 'target', internalType: 'address', type: 'address' }], name: 'AddressEmptyCode' },
  { type: 'error', inputs: [{ name: 'implementation', internalType: 'address', type: 'address' }], name: 'ERC1967InvalidImplementation' },
  { type: 'error', inputs: [], name: 'ERC1967NonPayable' },
  { type: 'error', inputs: [], name: 'FailedCall' },
  { type: 'event', anonymous: false, inputs: [{ name: 'implementation', internalType: 'address', type: 'address', indexed: true }], name: 'Upgraded' },
  { type: 'fallback', stateMutability: 'payable' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ERC1967Utils
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const erc1967UtilsAbi = [
  { type: 'error', inputs: [{ name: 'admin', internalType: 'address', type: 'address' }], name: 'ERC1967InvalidAdmin' },
  { type: 'error', inputs: [{ name: 'beacon', internalType: 'address', type: 'address' }], name: 'ERC1967InvalidBeacon' },
  { type: 'error', inputs: [{ name: 'implementation', internalType: 'address', type: 'address' }], name: 'ERC1967InvalidImplementation' },
  { type: 'error', inputs: [], name: 'ERC1967NonPayable' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ERC20
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const erc20Abi = [
  {
    type: 'error',
    inputs: [
      { name: 'spender', internalType: 'address', type: 'address' },
      { name: 'allowance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC20InsufficientAllowance',
  },
  {
    type: 'error',
    inputs: [
      { name: 'sender', internalType: 'address', type: 'address' },
      { name: 'balance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC20InsufficientBalance',
  },
  { type: 'error', inputs: [{ name: 'approver', internalType: 'address', type: 'address' }], name: 'ERC20InvalidApprover' },
  { type: 'error', inputs: [{ name: 'receiver', internalType: 'address', type: 'address' }], name: 'ERC20InvalidReceiver' },
  { type: 'error', inputs: [{ name: 'sender', internalType: 'address', type: 'address' }], name: 'ERC20InvalidSender' },
  { type: 'error', inputs: [{ name: 'spender', internalType: 'address', type: 'address' }], name: 'ERC20InvalidSpender' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address', indexed: true },
      { name: 'spender', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Approval',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'from', internalType: 'address', type: 'address', indexed: true },
      { name: 'to', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Transfer',
  },
  {
    type: 'function',
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address' },
      { name: 'spender', internalType: 'address', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'spender', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'decimals', outputs: [{ name: '', internalType: 'uint8', type: 'uint8' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'name', outputs: [{ name: '', internalType: 'string', type: 'string' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'symbol', outputs: [{ name: '', internalType: 'string', type: 'string' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'totalSupply', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transfer',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'from', internalType: 'address', type: 'address' },
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transferFrom',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Errors
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const errorsAbi = [
  { type: 'error', inputs: [], name: 'FailedCall' },
  { type: 'error', inputs: [], name: 'FailedDeployment' },
  {
    type: 'error',
    inputs: [
      { name: 'balance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'InsufficientBalance',
  },
  { type: 'error', inputs: [{ name: '', internalType: 'address', type: 'address' }], name: 'MissingPrecompile' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GianoPaymaster
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const gianoPaymasterAbi = [
  { type: 'constructor', inputs: [], stateMutability: 'nonpayable' },
  { type: 'error', inputs: [], name: 'AccessControlBadConfirmation' },
  {
    type: 'error',
    inputs: [
      { name: 'account', internalType: 'address', type: 'address' },
      { name: 'neededRole', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'AccessControlUnauthorizedAccount',
  },
  { type: 'error', inputs: [{ name: 'target', internalType: 'address', type: 'address' }], name: 'AddressEmptyCode' },
  { type: 'error', inputs: [{ name: 'signer', internalType: 'address', type: 'address' }], name: 'AlreadySigner' },
  { type: 'error', inputs: [], name: 'BadPaymasterData' },
  { type: 'error', inputs: [], name: 'DirectTransferNotAllowed' },
  { type: 'error', inputs: [{ name: 'implementation', internalType: 'address', type: 'address' }], name: 'ERC1967InvalidImplementation' },
  { type: 'error', inputs: [], name: 'ERC1967NonPayable' },
  { type: 'error', inputs: [], name: 'EnforcedPause' },
  {
    type: 'error',
    inputs: [
      { name: 'requested', internalType: 'uint256', type: 'uint256' },
      { name: 'available', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ExceedsTreasury',
  },
  { type: 'error', inputs: [], name: 'ExpectedPause' },
  { type: 'error', inputs: [], name: 'FailedCall' },
  {
    type: 'error',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'required', internalType: 'uint256', type: 'uint256' },
      { name: 'available', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'InsufficientTenantBalance',
  },
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [{ name: 'signer', internalType: 'address', type: 'address' }], name: 'NotASigner' },
  { type: 'error', inputs: [], name: 'NotEntryPoint' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  {
    type: 'error',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'caller', internalType: 'address', type: 'address' },
    ],
    name: 'NotWithdrawAddress',
  },
  { type: 'error', inputs: [], name: 'PaymasterPaused' },
  { type: 'error', inputs: [{ name: 'penaltyBps', internalType: 'uint16', type: 'uint16' }], name: 'PenaltyBpsTooHigh' },
  {
    type: 'error',
    inputs: [
      { name: 'bits', internalType: 'uint8', type: 'uint8' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'SafeCastOverflowedUintDowncast',
  },
  { type: 'error', inputs: [{ name: 'tenantId', internalType: 'bytes16', type: 'bytes16' }], name: 'TenantAlreadyRegistered' },
  { type: 'error', inputs: [{ name: 'tenantId', internalType: 'bytes16', type: 'bytes16' }], name: 'TenantDisabled' },
  {
    type: 'error',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'deficit', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'TenantInDeficit',
  },
  { type: 'error', inputs: [], name: 'UUPSUnauthorizedCallContext' },
  { type: 'error', inputs: [{ name: 'slot', internalType: 'bytes32', type: 'bytes32' }], name: 'UUPSUnsupportedProxiableUUID' },
  { type: 'error', inputs: [{ name: 'signer', internalType: 'address', type: 'address' }], name: 'UnauthorisedSigner' },
  { type: 'error', inputs: [{ name: 'tenantId', internalType: 'bytes16', type: 'bytes16' }], name: 'UnknownTenant' },
  { type: 'error', inputs: [], name: 'ZeroAddress' },
  { type: 'error', inputs: [], name: 'ZeroAmount' },
  { type: 'event', anonymous: false, inputs: [], name: 'EIP712DomainChanged' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'oldFeeWei', internalType: 'uint128', type: 'uint128', indexed: false },
      { name: 'newFeeWei', internalType: 'uint128', type: 'uint128', indexed: false },
    ],
    name: 'FeeChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'newTreasury', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'FeesAccrued',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'to', internalType: 'address', type: 'address', indexed: true },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'newTreasury', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'FeesWithdrawn',
  },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'name', internalType: 'string', type: 'string', indexed: true },
      { name: 'oldValue', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'newValue', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'ParamChanged',
  },
  { type: 'event', anonymous: false, inputs: [{ name: 'account', internalType: 'address', type: 'address', indexed: false }], name: 'Paused' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'previousAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'newAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
    ],
    name: 'RoleAdminChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleGranted',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleRevoked',
  },
  { type: 'event', anonymous: false, inputs: [{ name: 'signer', internalType: 'address', type: 'address', indexed: true }], name: 'SignerAdded' },
  { type: 'event', anonymous: false, inputs: [{ name: 'signer', internalType: 'address', type: 'address', indexed: true }], name: 'SignerRemoved' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'gasCostWei', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'feeWei', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'overheadWei', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'newBalance', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'success', internalType: 'bool', type: 'bool', indexed: false },
    ],
    name: 'Sponsored',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'shortfallWei', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'totalDeficitWei', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'SponsorshipDeficit',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'enabled', internalType: 'bool', type: 'bool', indexed: false },
      { name: 'actor', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'TenantEnabledChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'hasOverride', internalType: 'bool', type: 'bool', indexed: false },
      { name: 'feeWei', internalType: 'uint128', type: 'uint128', indexed: false },
    ],
    name: 'TenantFeeChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'from', internalType: 'address', type: 'address', indexed: true },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'deficitCleared', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'newBalance', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'TenantFunded',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'withdrawAddress', internalType: 'address', type: 'address', indexed: true },
      { name: 'slug', internalType: 'string', type: 'string', indexed: false },
    ],
    name: 'TenantRegistered',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'oldAddress', internalType: 'address', type: 'address', indexed: false },
      { name: 'newAddress', internalType: 'address', type: 'address', indexed: false },
    ],
    name: 'TenantWithdrawAddressChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16', indexed: true },
      { name: 'to', internalType: 'address', type: 'address', indexed: true },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'newBalance', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'TenantWithdrawn',
  },
  { type: 'event', anonymous: false, inputs: [{ name: 'account', internalType: 'address', type: 'address', indexed: false }], name: 'Unpaused' },
  { type: 'event', anonymous: false, inputs: [{ name: 'implementation', internalType: 'address', type: 'address', indexed: true }], name: 'Upgraded' },
  { type: 'function', inputs: [], name: 'DEFAULT_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'FEE_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'FEE_COLLECTOR_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'PARAM_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'PAUSER_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'ROLE_ADMIN', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'SIGNER_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'STAKE_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'TENANT_ADMIN_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'UPGRADER_ROLE', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'UPGRADE_INTERFACE_VERSION', outputs: [{ name: '', internalType: 'string', type: 'string' }], stateMutability: 'view' },
  { type: 'function', inputs: [{ name: 'signer', internalType: 'address', type: 'address' }], name: 'addSigner', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [{ name: 'unstakeDelaySec', internalType: 'uint32', type: 'uint32' }],
    name: 'addStake',
    outputs: [],
    stateMutability: 'payable',
  },
  { type: 'function', inputs: [], name: 'defaultFeeWei', outputs: [{ name: '', internalType: 'uint128', type: 'uint128' }], stateMutability: 'view' },
  { type: 'function', inputs: [{ name: 'tenantId', internalType: 'bytes16', type: 'bytes16' }], name: 'depositFor', outputs: [], stateMutability: 'payable' },
  {
    type: 'function',
    inputs: [],
    name: 'eip712Domain',
    outputs: [
      { name: 'fields', internalType: 'bytes1', type: 'bytes1' },
      { name: 'name', internalType: 'string', type: 'string' },
      { name: 'version', internalType: 'string', type: 'string' },
      { name: 'chainId', internalType: 'uint256', type: 'uint256' },
      { name: 'verifyingContract', internalType: 'address', type: 'address' },
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'extensions', internalType: 'uint256[]', type: 'uint256[]' },
    ],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'entryPoint', outputs: [{ name: '', internalType: 'contract IEntryPoint', type: 'address' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'tenantId', internalType: 'bytes16', type: 'bytes16' }],
    name: 'feeFor',
    outputs: [{ name: '', internalType: 'uint128', type: 'uint128' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'getDeposit', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleAdmin',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'index', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'getRoleMember',
    outputs: [{ name: '', internalType: 'address', type: 'address' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleMemberCount',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleMembers',
    outputs: [{ name: '', internalType: 'address[]', type: 'address[]' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'getSigners', outputs: [{ name: '', internalType: 'address[]', type: 'address[]' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'tenantId', internalType: 'bytes16', type: 'bytes16' }],
    name: 'getTenant',
    outputs: [
      {
        name: '',
        internalType: 'struct GianoPaymaster.Tenant',
        type: 'tuple',
        components: [
          { name: 'registered', internalType: 'bool', type: 'bool' },
          { name: 'enabled', internalType: 'bool', type: 'bool' },
          { name: 'hasFeeOverride', internalType: 'bool', type: 'bool' },
          { name: 'withdrawAddress', internalType: 'address', type: 'address' },
          { name: 'balance', internalType: 'uint128', type: 'uint128' },
          { name: 'deficit', internalType: 'uint128', type: 'uint128' },
          { name: 'feeWeiOverride', internalType: 'uint128', type: 'uint128' },
        ],
      },
    ],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'getTenantIds', outputs: [{ name: 'ids', internalType: 'bytes16[]', type: 'bytes16[]' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'start', internalType: 'uint256', type: 'uint256' },
      { name: 'count', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'getTenants',
    outputs: [
      { name: 'ids', internalType: 'bytes16[]', type: 'bytes16[]' },
      {
        name: 'records',
        internalType: 'struct GianoPaymaster.Tenant[]',
        type: 'tuple[]',
        components: [
          { name: 'registered', internalType: 'bool', type: 'bool' },
          { name: 'enabled', internalType: 'bool', type: 'bool' },
          { name: 'hasFeeOverride', internalType: 'bool', type: 'bool' },
          { name: 'withdrawAddress', internalType: 'address', type: 'address' },
          { name: 'balance', internalType: 'uint128', type: 'uint128' },
          { name: 'deficit', internalType: 'uint128', type: 'uint128' },
          { name: 'feeWeiOverride', internalType: 'uint128', type: 'uint128' },
        ],
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'grantRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'hasRole',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'entryPoint_', internalType: 'address', type: 'address' },
      { name: 'roleAdmin', internalType: 'address', type: 'address' },
      { name: 'defaultFeeWei_', internalType: 'uint128', type: 'uint128' },
      { name: 'postOpGasAllowance_', internalType: 'uint32', type: 'uint32' },
      { name: 'penaltyBps_', internalType: 'uint16', type: 'uint16' },
    ],
    name: 'initialize',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'signer', internalType: 'address', type: 'address' }],
    name: 'isSigner',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'pause', outputs: [], stateMutability: 'nonpayable' },
  { type: 'function', inputs: [], name: 'paused', outputs: [{ name: '', internalType: 'bool', type: 'bool' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'penaltyBps', outputs: [{ name: '', internalType: 'uint16', type: 'uint16' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'mode', internalType: 'enum IPaymaster.PostOpMode', type: 'uint8' },
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'actualGasCost', internalType: 'uint256', type: 'uint256' },
      { name: 'actualUserOpFeePerGas', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'postOp',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [], name: 'postOpGasAllowance', outputs: [{ name: '', internalType: 'uint32', type: 'uint32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'proxiableUUID', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'withdrawAddress', internalType: 'address', type: 'address' },
      { name: 'slug', internalType: 'string', type: 'string' },
    ],
    name: 'registerTenant',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'signer', internalType: 'address', type: 'address' }],
    name: 'removeSigner',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'callerConfirmation', internalType: 'address', type: 'address' },
    ],
    name: 'renounceRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'revokeRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'feeWei', internalType: 'uint128', type: 'uint128' }],
    name: 'setDefaultFee',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [{ name: 'bps', internalType: 'uint16', type: 'uint16' }], name: 'setPenaltyBps', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [{ name: 'gasUnits', internalType: 'uint32', type: 'uint32' }],
    name: 'setPostOpGasAllowance',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'enabled', internalType: 'bool', type: 'bool' },
    ],
    name: 'setTenantEnabled',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'hasOverride', internalType: 'bool', type: 'bool' },
      { name: 'feeWei', internalType: 'uint128', type: 'uint128' },
    ],
    name: 'setTenantFee',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'withdrawAddress', internalType: 'address', type: 'address' },
    ],
    name: 'setTenantWithdrawAddress',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'index', internalType: 'uint256', type: 'uint256' }],
    name: 'signerAt',
    outputs: [{ name: '', internalType: 'address', type: 'address' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'signerCount', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'interfaceId', internalType: 'bytes4', type: 'bytes4' }],
    name: 'supportsInterface',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'tenantCount', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'index', internalType: 'uint256', type: 'uint256' }],
    name: 'tenantIdAt',
    outputs: [{ name: '', internalType: 'bytes16', type: 'bytes16' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'treasury', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'unlockStake', outputs: [], stateMutability: 'nonpayable' },
  { type: 'function', inputs: [], name: 'unpause', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [
      { name: 'newImplementation', internalType: 'address', type: 'address' },
      { name: 'data', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'upgradeToAndCall',
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'maxCost', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'validatePaymasterUserOp',
    outputs: [
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'validationData', internalType: 'uint256', type: 'uint256' },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'amount', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'withdrawFees',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'to', internalType: 'address payable', type: 'address' }],
    name: 'withdrawStake',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'tenantId', internalType: 'bytes16', type: 'bytes16' },
      { name: 'amount', internalType: 'uint256', type: 'uint256' },
      { name: 'to', internalType: 'address', type: 'address' },
    ],
    name: 'withdrawTenant',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'receive', stateMutability: 'payable' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GianoPaymasterDeployer
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const gianoPaymasterDeployerAbi = [
  { type: 'error', inputs: [], name: 'Create2EmptyBytecode' },
  { type: 'error', inputs: [], name: 'FailedDeployment' },
  { type: 'error', inputs: [{ name: 'reason', internalType: 'bytes', type: 'bytes' }], name: 'InitialisationFailed' },
  {
    type: 'error',
    inputs: [
      { name: 'balance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'InsufficientBalance',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'proxy', internalType: 'address', type: 'address', indexed: true },
      { name: 'implementation', internalType: 'address', type: 'address', indexed: true },
      { name: 'salt', internalType: 'bytes32', type: 'bytes32', indexed: false },
    ],
    name: 'PaymasterDeployed',
  },
  {
    type: 'function',
    inputs: [
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'implementation', internalType: 'address', type: 'address' },
      { name: 'initCalldata', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'deploy',
    outputs: [{ name: 'proxy', internalType: 'address', type: 'address' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'implementation', internalType: 'address', type: 'address' },
    ],
    name: 'predict',
    outputs: [{ name: '', internalType: 'address', type: 'address' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GianoSmartWallet
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const gianoSmartWalletAbi = [
  { type: 'constructor', inputs: [], stateMutability: 'nonpayable' },
  { type: 'error', inputs: [{ name: 'owner', internalType: 'bytes', type: 'bytes' }], name: 'AlreadyOwner' },
  { type: 'error', inputs: [], name: 'FnSelectorNotRecognized' },
  { type: 'error', inputs: [], name: 'Initialized' },
  { type: 'error', inputs: [{ name: 'owner', internalType: 'bytes', type: 'bytes' }], name: 'InvalidEthereumAddressOwner' },
  { type: 'error', inputs: [{ name: 'implementation', internalType: 'address', type: 'address' }], name: 'InvalidImplementation' },
  { type: 'error', inputs: [{ name: 'key', internalType: 'uint256', type: 'uint256' }], name: 'InvalidNonceKey' },
  { type: 'error', inputs: [{ name: 'owner', internalType: 'bytes', type: 'bytes' }], name: 'InvalidOwnerBytesLength' },
  { type: 'error', inputs: [], name: 'InvalidSignature' },
  { type: 'error', inputs: [], name: 'LastOwner' },
  { type: 'error', inputs: [{ name: 'index', internalType: 'uint256', type: 'uint256' }], name: 'NoOwnerAtIndex' },
  { type: 'error', inputs: [{ name: 'ownersRemaining', internalType: 'uint256', type: 'uint256' }], name: 'NotLastOwner' },
  { type: 'error', inputs: [{ name: 'selector', internalType: 'bytes4', type: 'bytes4' }], name: 'SelectorNotAllowed' },
  {
    type: 'error',
    inputs: [
      { name: 'expiredAt', internalType: 'uint256', type: 'uint256' },
      { name: 'currentTimestamp', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'SignatureExpired',
  },
  { type: 'error', inputs: [], name: 'Unauthorized' },
  { type: 'error', inputs: [], name: 'UnauthorizedCallContext' },
  { type: 'error', inputs: [], name: 'UpgradeFailed' },
  {
    type: 'error',
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256' },
      { name: 'expectedOwner', internalType: 'bytes', type: 'bytes' },
      { name: 'actualOwner', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'WrongOwnerAtIndex',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256', indexed: true },
      { name: 'owner', internalType: 'bytes', type: 'bytes', indexed: false },
    ],
    name: 'AddOwner',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256', indexed: true },
      { name: 'owner', internalType: 'bytes', type: 'bytes', indexed: false },
    ],
    name: 'RemoveOwner',
  },
  { type: 'event', anonymous: false, inputs: [{ name: 'implementation', internalType: 'address', type: 'address', indexed: true }], name: 'Upgraded' },
  { type: 'fallback', stateMutability: 'payable' },
  { type: 'function', inputs: [], name: 'REPLAYABLE_NONCE_KEY', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'owner', internalType: 'address', type: 'address' }],
    name: 'addOwnerAddress',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'x', internalType: 'bytes32', type: 'bytes32' },
      { name: 'y', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'addOwnerPublicKey',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'functionSelector', internalType: 'bytes4', type: 'bytes4' }],
    name: 'canSkipChainIdValidation',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'pure',
  },
  { type: 'function', inputs: [], name: 'domainSeparator', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [],
    name: 'eip712Domain',
    outputs: [
      { name: 'fields', internalType: 'bytes1', type: 'bytes1' },
      { name: 'name', internalType: 'string', type: 'string' },
      { name: 'version', internalType: 'string', type: 'string' },
      { name: 'chainId', internalType: 'uint256', type: 'uint256' },
      { name: 'verifyingContract', internalType: 'address', type: 'address' },
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'extensions', internalType: 'uint256[]', type: 'uint256[]' },
    ],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'entryPoint', outputs: [{ name: '', internalType: 'address', type: 'address' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'target', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
      { name: 'data', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'execute',
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'calls',
        internalType: 'struct GianoSmartWallet.Call[]',
        type: 'tuple[]',
        components: [
          { name: 'target', internalType: 'address', type: 'address' },
          { name: 'value', internalType: 'uint256', type: 'uint256' },
          { name: 'data', internalType: 'bytes', type: 'bytes' },
        ],
      },
    ],
    name: 'executeBatch',
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    inputs: [{ name: 'calls', internalType: 'bytes[]', type: 'bytes[]' }],
    name: 'executeWithoutChainIdValidation',
    outputs: [],
    stateMutability: 'payable',
  },
  { type: 'function', inputs: [], name: 'getSignatureLifetime', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
    ],
    name: 'getUserOpHashWithoutChainId',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'implementation', outputs: [{ name: '$', internalType: 'address', type: 'address' }], stateMutability: 'view' },
  { type: 'function', inputs: [{ name: 'owners', internalType: 'bytes[]', type: 'bytes[]' }], name: 'initialize', outputs: [], stateMutability: 'payable' },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'isOwnerAddress',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'bytes', type: 'bytes' }],
    name: 'isOwnerBytes',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'x', internalType: 'bytes32', type: 'bytes32' },
      { name: 'y', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'isOwnerPublicKey',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'hash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'signature', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'isValidSignature',
    outputs: [{ name: 'result', internalType: 'bytes4', type: 'bytes4' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'nextOwnerIndex', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'index', internalType: 'uint256', type: 'uint256' }],
    name: 'ownerAtIndex',
    outputs: [{ name: '', internalType: 'bytes', type: 'bytes' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'ownerCount', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'proxiableUUID', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256' },
      { name: 'owner', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'removeLastOwner',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256' },
      { name: 'owner', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'removeOwnerAtIndex',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [], name: 'removedOwnersCount', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'hash', internalType: 'bytes32', type: 'bytes32' }],
    name: 'replaySafeHash',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'call',
        internalType: 'struct StaticCall',
        type: 'tuple',
        components: [
          { name: 'target', internalType: 'address', type: 'address' },
          { name: 'data', internalType: 'bytes', type: 'bytes' },
          { name: 'signedAt', internalType: 'uint256', type: 'uint256' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
    ],
    name: 'signedStaticCall',
    outputs: [{ name: '', internalType: 'bytes', type: 'bytes' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'newImplementation', internalType: 'address', type: 'address' },
      { name: 'data', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'upgradeToAndCall',
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'missingAccountFunds', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'validateUserOp',
    outputs: [{ name: 'validationData', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'nonpayable',
  },
  { type: 'receive', stateMutability: 'payable' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// GianoSmartWalletFactory
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const gianoSmartWalletFactoryAbi = [
  { type: 'constructor', inputs: [{ name: 'implementation_', internalType: 'address', type: 'address' }], stateMutability: 'payable' },
  { type: 'error', inputs: [], name: 'ImplementationUndeployed' },
  { type: 'error', inputs: [], name: 'OwnerRequired' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'owners', internalType: 'bytes[]', type: 'bytes[]', indexed: false },
      { name: 'nonce', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'AccountCreated',
  },
  {
    type: 'function',
    inputs: [
      { name: 'owners', internalType: 'bytes[]', type: 'bytes[]' },
      { name: 'nonce', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'createAccount',
    outputs: [{ name: 'account', internalType: 'contract GianoSmartWallet', type: 'address' }],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'owners', internalType: 'bytes[]', type: 'bytes[]' },
      { name: 'nonce', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'getAddress',
    outputs: [{ name: '', internalType: 'address', type: 'address' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'implementation', outputs: [{ name: '', internalType: 'address', type: 'address' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'initCodeHash', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IAccessControl
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iAccessControlAbi = [
  { type: 'error', inputs: [], name: 'AccessControlBadConfirmation' },
  {
    type: 'error',
    inputs: [
      { name: 'account', internalType: 'address', type: 'address' },
      { name: 'neededRole', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'AccessControlUnauthorizedAccount',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'previousAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'newAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
    ],
    name: 'RoleAdminChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleGranted',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleRevoked',
  },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleAdmin',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'grantRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'hasRole',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'callerConfirmation', internalType: 'address', type: 'address' },
    ],
    name: 'renounceRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'revokeRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IAccessControlEnumerable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iAccessControlEnumerableAbi = [
  { type: 'error', inputs: [], name: 'AccessControlBadConfirmation' },
  {
    type: 'error',
    inputs: [
      { name: 'account', internalType: 'address', type: 'address' },
      { name: 'neededRole', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'AccessControlUnauthorizedAccount',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'previousAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'newAdminRole', internalType: 'bytes32', type: 'bytes32', indexed: true },
    ],
    name: 'RoleAdminChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleGranted',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'RoleRevoked',
  },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleAdmin',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'index', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'getRoleMember',
    outputs: [{ name: '', internalType: 'address', type: 'address' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'role', internalType: 'bytes32', type: 'bytes32' }],
    name: 'getRoleMemberCount',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'grantRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'hasRole',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'callerConfirmation', internalType: 'address', type: 'address' },
    ],
    name: 'renounceRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'role', internalType: 'bytes32', type: 'bytes32' },
      { name: 'account', internalType: 'address', type: 'address' },
    ],
    name: 'revokeRole',
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IAccount
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iAccountAbi = [
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'missingAccountFunds', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'validateUserOp',
    outputs: [{ name: 'validationData', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IAggregator
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iAggregatorAbi = [
  {
    type: 'function',
    inputs: [
      {
        name: 'userOps',
        internalType: 'struct PackedUserOperation[]',
        type: 'tuple[]',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
    ],
    name: 'aggregateSignatures',
    outputs: [{ name: 'aggregatedSignature', internalType: 'bytes', type: 'bytes' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOps',
        internalType: 'struct PackedUserOperation[]',
        type: 'tuple[]',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'signature', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'validateSignatures',
    outputs: [],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
    ],
    name: 'validateUserOpSignature',
    outputs: [{ name: 'sigForUserOp', internalType: 'bytes', type: 'bytes' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IBeacon
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iBeaconAbi = [
  { type: 'function', inputs: [], name: 'implementation', outputs: [{ name: '', internalType: 'address', type: 'address' }], stateMutability: 'view' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC1155Errors
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc1155ErrorsAbi = [
  {
    type: 'error',
    inputs: [
      { name: 'sender', internalType: 'address', type: 'address' },
      { name: 'balance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
      { name: 'tokenId', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC1155InsufficientBalance',
  },
  { type: 'error', inputs: [{ name: 'approver', internalType: 'address', type: 'address' }], name: 'ERC1155InvalidApprover' },
  {
    type: 'error',
    inputs: [
      { name: 'idsLength', internalType: 'uint256', type: 'uint256' },
      { name: 'valuesLength', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC1155InvalidArrayLength',
  },
  { type: 'error', inputs: [{ name: 'operator', internalType: 'address', type: 'address' }], name: 'ERC1155InvalidOperator' },
  { type: 'error', inputs: [{ name: 'receiver', internalType: 'address', type: 'address' }], name: 'ERC1155InvalidReceiver' },
  { type: 'error', inputs: [{ name: 'sender', internalType: 'address', type: 'address' }], name: 'ERC1155InvalidSender' },
  {
    type: 'error',
    inputs: [
      { name: 'operator', internalType: 'address', type: 'address' },
      { name: 'owner', internalType: 'address', type: 'address' },
    ],
    name: 'ERC1155MissingApprovalForAll',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC1271
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc1271Abi = [
  {
    type: 'function',
    inputs: [
      { name: 'hash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'signature', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'isValidSignature',
    outputs: [{ name: 'magicValue', internalType: 'bytes4', type: 'bytes4' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC165
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc165Abi = [
  {
    type: 'function',
    inputs: [{ name: 'interfaceId', internalType: 'bytes4', type: 'bytes4' }],
    name: 'supportsInterface',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC1822Proxiable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc1822ProxiableAbi = [
  { type: 'function', inputs: [], name: 'proxiableUUID', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC1967
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc1967Abi = [
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'previousAdmin', internalType: 'address', type: 'address', indexed: false },
      { name: 'newAdmin', internalType: 'address', type: 'address', indexed: false },
    ],
    name: 'AdminChanged',
  },
  { type: 'event', anonymous: false, inputs: [{ name: 'beacon', internalType: 'address', type: 'address', indexed: true }], name: 'BeaconUpgraded' },
  { type: 'event', anonymous: false, inputs: [{ name: 'implementation', internalType: 'address', type: 'address', indexed: true }], name: 'Upgraded' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC20
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc20Abi = [
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address', indexed: true },
      { name: 'spender', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Approval',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'from', internalType: 'address', type: 'address', indexed: true },
      { name: 'to', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Transfer',
  },
  {
    type: 'function',
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address' },
      { name: 'spender', internalType: 'address', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'spender', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'totalSupply', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transfer',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'from', internalType: 'address', type: 'address' },
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transferFrom',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC20Errors
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc20ErrorsAbi = [
  {
    type: 'error',
    inputs: [
      { name: 'spender', internalType: 'address', type: 'address' },
      { name: 'allowance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC20InsufficientAllowance',
  },
  {
    type: 'error',
    inputs: [
      { name: 'sender', internalType: 'address', type: 'address' },
      { name: 'balance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC20InsufficientBalance',
  },
  { type: 'error', inputs: [{ name: 'approver', internalType: 'address', type: 'address' }], name: 'ERC20InvalidApprover' },
  { type: 'error', inputs: [{ name: 'receiver', internalType: 'address', type: 'address' }], name: 'ERC20InvalidReceiver' },
  { type: 'error', inputs: [{ name: 'sender', internalType: 'address', type: 'address' }], name: 'ERC20InvalidSender' },
  { type: 'error', inputs: [{ name: 'spender', internalType: 'address', type: 'address' }], name: 'ERC20InvalidSpender' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC20Metadata
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc20MetadataAbi = [
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address', indexed: true },
      { name: 'spender', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Approval',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'from', internalType: 'address', type: 'address', indexed: true },
      { name: 'to', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Transfer',
  },
  {
    type: 'function',
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address' },
      { name: 'spender', internalType: 'address', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'spender', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'decimals', outputs: [{ name: '', internalType: 'uint8', type: 'uint8' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'name', outputs: [{ name: '', internalType: 'string', type: 'string' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'symbol', outputs: [{ name: '', internalType: 'string', type: 'string' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'totalSupply', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transfer',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'from', internalType: 'address', type: 'address' },
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transferFrom',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC5267
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc5267Abi = [
  { type: 'event', anonymous: false, inputs: [], name: 'EIP712DomainChanged' },
  {
    type: 'function',
    inputs: [],
    name: 'eip712Domain',
    outputs: [
      { name: 'fields', internalType: 'bytes1', type: 'bytes1' },
      { name: 'name', internalType: 'string', type: 'string' },
      { name: 'version', internalType: 'string', type: 'string' },
      { name: 'chainId', internalType: 'uint256', type: 'uint256' },
      { name: 'verifyingContract', internalType: 'address', type: 'address' },
      { name: 'salt', internalType: 'bytes32', type: 'bytes32' },
      { name: 'extensions', internalType: 'uint256[]', type: 'uint256[]' },
    ],
    stateMutability: 'view',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IERC721Errors
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ierc721ErrorsAbi = [
  {
    type: 'error',
    inputs: [
      { name: 'sender', internalType: 'address', type: 'address' },
      { name: 'tokenId', internalType: 'uint256', type: 'uint256' },
      { name: 'owner', internalType: 'address', type: 'address' },
    ],
    name: 'ERC721IncorrectOwner',
  },
  {
    type: 'error',
    inputs: [
      { name: 'operator', internalType: 'address', type: 'address' },
      { name: 'tokenId', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC721InsufficientApproval',
  },
  { type: 'error', inputs: [{ name: 'approver', internalType: 'address', type: 'address' }], name: 'ERC721InvalidApprover' },
  { type: 'error', inputs: [{ name: 'operator', internalType: 'address', type: 'address' }], name: 'ERC721InvalidOperator' },
  { type: 'error', inputs: [{ name: 'owner', internalType: 'address', type: 'address' }], name: 'ERC721InvalidOwner' },
  { type: 'error', inputs: [{ name: 'receiver', internalType: 'address', type: 'address' }], name: 'ERC721InvalidReceiver' },
  { type: 'error', inputs: [{ name: 'sender', internalType: 'address', type: 'address' }], name: 'ERC721InvalidSender' },
  { type: 'error', inputs: [{ name: 'tokenId', internalType: 'uint256', type: 'uint256' }], name: 'ERC721NonexistentToken' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IEntryPoint
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iEntryPointAbi = [
  {
    type: 'error',
    inputs: [
      { name: 'success', internalType: 'bool', type: 'bool' },
      { name: 'ret', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'DelegateAndRevert',
  },
  {
    type: 'error',
    inputs: [
      { name: 'opIndex', internalType: 'uint256', type: 'uint256' },
      { name: 'reason', internalType: 'string', type: 'string' },
    ],
    name: 'FailedOp',
  },
  {
    type: 'error',
    inputs: [
      { name: 'opIndex', internalType: 'uint256', type: 'uint256' },
      { name: 'reason', internalType: 'string', type: 'string' },
      { name: 'inner', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'FailedOpWithRevert',
  },
  { type: 'error', inputs: [{ name: 'returnData', internalType: 'bytes', type: 'bytes' }], name: 'PostOpReverted' },
  { type: 'error', inputs: [{ name: 'sender', internalType: 'address', type: 'address' }], name: 'SenderAddressResult' },
  { type: 'error', inputs: [{ name: 'aggregator', internalType: 'address', type: 'address' }], name: 'SignatureValidationFailed' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
      { name: 'factory', internalType: 'address', type: 'address', indexed: false },
      { name: 'paymaster', internalType: 'address', type: 'address', indexed: false },
    ],
    name: 'AccountDeployed',
  },
  { type: 'event', anonymous: false, inputs: [], name: 'BeforeExecution' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'totalDeposit', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Deposited',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
      { name: 'nonce', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'revertReason', internalType: 'bytes', type: 'bytes', indexed: false },
    ],
    name: 'PostOpRevertReason',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [{ name: 'aggregator', internalType: 'address', type: 'address', indexed: true }],
    name: 'SignatureAggregatorChanged',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'totalStaked', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'unstakeDelaySec', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'StakeLocked',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'withdrawTime', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'StakeUnlocked',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'withdrawAddress', internalType: 'address', type: 'address', indexed: false },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'StakeWithdrawn',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
      { name: 'paymaster', internalType: 'address', type: 'address', indexed: true },
      { name: 'nonce', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'success', internalType: 'bool', type: 'bool', indexed: false },
      { name: 'actualGasCost', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'actualGasUsed', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'UserOperationEvent',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
      { name: 'nonce', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'UserOperationPrefundTooLow',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32', indexed: true },
      { name: 'sender', internalType: 'address', type: 'address', indexed: true },
      { name: 'nonce', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'revertReason', internalType: 'bytes', type: 'bytes', indexed: false },
    ],
    name: 'UserOperationRevertReason',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'withdrawAddress', internalType: 'address', type: 'address', indexed: false },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Withdrawn',
  },
  {
    type: 'function',
    inputs: [{ name: '_unstakeDelaySec', internalType: 'uint32', type: 'uint32' }],
    name: 'addStake',
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'target', internalType: 'address', type: 'address' },
      { name: 'data', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'delegateAndRevert',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [{ name: 'account', internalType: 'address', type: 'address' }], name: 'depositTo', outputs: [], stateMutability: 'payable' },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'getDepositInfo',
    outputs: [
      {
        name: 'info',
        internalType: 'struct IStakeManager.DepositInfo',
        type: 'tuple',
        components: [
          { name: 'deposit', internalType: 'uint256', type: 'uint256' },
          { name: 'staked', internalType: 'bool', type: 'bool' },
          { name: 'stake', internalType: 'uint112', type: 'uint112' },
          { name: 'unstakeDelaySec', internalType: 'uint32', type: 'uint32' },
          { name: 'withdrawTime', internalType: 'uint48', type: 'uint48' },
        ],
      },
    ],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'sender', internalType: 'address', type: 'address' },
      { name: 'key', internalType: 'uint192', type: 'uint192' },
    ],
    name: 'getNonce',
    outputs: [{ name: 'nonce', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'initCode', internalType: 'bytes', type: 'bytes' }],
    name: 'getSenderAddress',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
    ],
    name: 'getUserOpHash',
    outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'opsPerAggregator',
        internalType: 'struct IEntryPoint.UserOpsPerAggregator[]',
        type: 'tuple[]',
        components: [
          {
            name: 'userOps',
            internalType: 'struct PackedUserOperation[]',
            type: 'tuple[]',
            components: [
              { name: 'sender', internalType: 'address', type: 'address' },
              { name: 'nonce', internalType: 'uint256', type: 'uint256' },
              { name: 'initCode', internalType: 'bytes', type: 'bytes' },
              { name: 'callData', internalType: 'bytes', type: 'bytes' },
              { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
              { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
              { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
              { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
              { name: 'signature', internalType: 'bytes', type: 'bytes' },
            ],
          },
          { name: 'aggregator', internalType: 'contract IAggregator', type: 'address' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'beneficiary', internalType: 'address payable', type: 'address' },
    ],
    name: 'handleAggregatedOps',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'ops',
        internalType: 'struct PackedUserOperation[]',
        type: 'tuple[]',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'beneficiary', internalType: 'address payable', type: 'address' },
    ],
    name: 'handleOps',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [{ name: 'key', internalType: 'uint192', type: 'uint192' }], name: 'incrementNonce', outputs: [], stateMutability: 'nonpayable' },
  { type: 'function', inputs: [], name: 'unlockStake', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [{ name: 'withdrawAddress', internalType: 'address payable', type: 'address' }],
    name: 'withdrawStake',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'withdrawAddress', internalType: 'address payable', type: 'address' },
      { name: 'withdrawAmount', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'withdrawTo',
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// INonceManager
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iNonceManagerAbi = [
  {
    type: 'function',
    inputs: [
      { name: 'sender', internalType: 'address', type: 'address' },
      { name: 'key', internalType: 'uint192', type: 'uint192' },
    ],
    name: 'getNonce',
    outputs: [{ name: 'nonce', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [{ name: 'key', internalType: 'uint192', type: 'uint192' }], name: 'incrementNonce', outputs: [], stateMutability: 'nonpayable' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IPaymaster
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iPaymasterAbi = [
  {
    type: 'function',
    inputs: [
      { name: 'mode', internalType: 'enum IPaymaster.PostOpMode', type: 'uint8' },
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'actualGasCost', internalType: 'uint256', type: 'uint256' },
      { name: 'actualUserOpFeePerGas', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'postOp',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'maxCost', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'validatePaymasterUserOp',
    outputs: [
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'validationData', internalType: 'uint256', type: 'uint256' },
    ],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// IStakeManager
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const iStakeManagerAbi = [
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'totalDeposit', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Deposited',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'totalStaked', internalType: 'uint256', type: 'uint256', indexed: false },
      { name: 'unstakeDelaySec', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'StakeLocked',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'withdrawTime', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'StakeUnlocked',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'withdrawAddress', internalType: 'address', type: 'address', indexed: false },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'StakeWithdrawn',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'account', internalType: 'address', type: 'address', indexed: true },
      { name: 'withdrawAddress', internalType: 'address', type: 'address', indexed: false },
      { name: 'amount', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Withdrawn',
  },
  {
    type: 'function',
    inputs: [{ name: '_unstakeDelaySec', internalType: 'uint32', type: 'uint32' }],
    name: 'addStake',
    outputs: [],
    stateMutability: 'payable',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [{ name: 'account', internalType: 'address', type: 'address' }], name: 'depositTo', outputs: [], stateMutability: 'payable' },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'getDepositInfo',
    outputs: [
      {
        name: 'info',
        internalType: 'struct IStakeManager.DepositInfo',
        type: 'tuple',
        components: [
          { name: 'deposit', internalType: 'uint256', type: 'uint256' },
          { name: 'staked', internalType: 'bool', type: 'bool' },
          { name: 'stake', internalType: 'uint112', type: 'uint112' },
          { name: 'unstakeDelaySec', internalType: 'uint32', type: 'uint32' },
          { name: 'withdrawTime', internalType: 'uint48', type: 'uint48' },
        ],
      },
    ],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'unlockStake', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [{ name: 'withdrawAddress', internalType: 'address payable', type: 'address' }],
    name: 'withdrawStake',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'withdrawAddress', internalType: 'address payable', type: 'address' },
      { name: 'withdrawAmount', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'withdrawTo',
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Initializable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const initializableAbi = [
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LibClone
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const libCloneAbi = [
  { type: 'error', inputs: [], name: 'DeploymentFailed' },
  { type: 'error', inputs: [], name: 'ETHTransferFailed' },
  { type: 'error', inputs: [], name: 'SaltDoesNotStartWith' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// LibString
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const libStringAbi = [
  { type: 'error', inputs: [], name: 'HexLengthInsufficient' },
  { type: 'error', inputs: [], name: 'StringNot7BitASCII' },
  { type: 'error', inputs: [], name: 'TooBigForSmallString' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// MultiOwnable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const multiOwnableAbi = [
  { type: 'error', inputs: [{ name: 'owner', internalType: 'bytes', type: 'bytes' }], name: 'AlreadyOwner' },
  { type: 'error', inputs: [{ name: 'owner', internalType: 'bytes', type: 'bytes' }], name: 'InvalidEthereumAddressOwner' },
  { type: 'error', inputs: [{ name: 'owner', internalType: 'bytes', type: 'bytes' }], name: 'InvalidOwnerBytesLength' },
  { type: 'error', inputs: [], name: 'LastOwner' },
  { type: 'error', inputs: [{ name: 'index', internalType: 'uint256', type: 'uint256' }], name: 'NoOwnerAtIndex' },
  { type: 'error', inputs: [{ name: 'ownersRemaining', internalType: 'uint256', type: 'uint256' }], name: 'NotLastOwner' },
  { type: 'error', inputs: [], name: 'Unauthorized' },
  {
    type: 'error',
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256' },
      { name: 'expectedOwner', internalType: 'bytes', type: 'bytes' },
      { name: 'actualOwner', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'WrongOwnerAtIndex',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256', indexed: true },
      { name: 'owner', internalType: 'bytes', type: 'bytes', indexed: false },
    ],
    name: 'AddOwner',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256', indexed: true },
      { name: 'owner', internalType: 'bytes', type: 'bytes', indexed: false },
    ],
    name: 'RemoveOwner',
  },
  {
    type: 'function',
    inputs: [{ name: 'owner', internalType: 'address', type: 'address' }],
    name: 'addOwnerAddress',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'x', internalType: 'bytes32', type: 'bytes32' },
      { name: 'y', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'addOwnerPublicKey',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'isOwnerAddress',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'bytes', type: 'bytes' }],
    name: 'isOwnerBytes',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'x', internalType: 'bytes32', type: 'bytes32' },
      { name: 'y', internalType: 'bytes32', type: 'bytes32' },
    ],
    name: 'isOwnerPublicKey',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'nextOwnerIndex', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'index', internalType: 'uint256', type: 'uint256' }],
    name: 'ownerAtIndex',
    outputs: [{ name: '', internalType: 'bytes', type: 'bytes' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'ownerCount', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256' },
      { name: 'owner', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'removeLastOwner',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'index', internalType: 'uint256', type: 'uint256' },
      { name: 'owner', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'removeOwnerAtIndex',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [], name: 'removedOwnersCount', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Ownable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const ownableAbi = [
  { type: 'error', inputs: [{ name: 'owner', internalType: 'address', type: 'address' }], name: 'OwnableInvalidOwner' },
  { type: 'error', inputs: [{ name: 'account', internalType: 'address', type: 'address' }], name: 'OwnableUnauthorizedAccount' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'previousOwner', internalType: 'address', type: 'address', indexed: true },
      { name: 'newOwner', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'OwnershipTransferred',
  },
  { type: 'function', inputs: [], name: 'owner', outputs: [{ name: '', internalType: 'address', type: 'address' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'renounceOwnership', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [{ name: 'newOwner', internalType: 'address', type: 'address' }],
    name: 'transferOwnership',
    outputs: [],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PausableUpgradeable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const pausableUpgradeableAbi = [
  { type: 'error', inputs: [], name: 'EnforcedPause' },
  { type: 'error', inputs: [], name: 'ExpectedPause' },
  { type: 'error', inputs: [], name: 'InvalidInitialization' },
  { type: 'error', inputs: [], name: 'NotInitializing' },
  { type: 'event', anonymous: false, inputs: [{ name: 'version', internalType: 'uint64', type: 'uint64', indexed: false }], name: 'Initialized' },
  { type: 'event', anonymous: false, inputs: [{ name: 'account', internalType: 'address', type: 'address', indexed: false }], name: 'Paused' },
  { type: 'event', anonymous: false, inputs: [{ name: 'account', internalType: 'address', type: 'address', indexed: false }], name: 'Unpaused' },
  { type: 'function', inputs: [], name: 'paused', outputs: [{ name: '', internalType: 'bool', type: 'bool' }], stateMutability: 'view' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PermissivePaymaster
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const permissivePaymasterAbi = [
  { type: 'constructor', inputs: [{ name: '_entryPoint', internalType: 'address', type: 'address' }], stateMutability: 'nonpayable' },
  { type: 'error', inputs: [], name: 'OnlyEntrypoint' },
  { type: 'error', inputs: [{ name: 'owner', internalType: 'address', type: 'address' }], name: 'OwnableInvalidOwner' },
  { type: 'error', inputs: [{ name: 'account', internalType: 'address', type: 'address' }], name: 'OwnableUnauthorizedAccount' },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'previousOwner', internalType: 'address', type: 'address', indexed: true },
      { name: 'newOwner', internalType: 'address', type: 'address', indexed: true },
    ],
    name: 'OwnershipTransferred',
  },
  {
    type: 'function',
    inputs: [{ name: 'unstakeDelaySec', internalType: 'uint32', type: 'uint32' }],
    name: 'addStake',
    outputs: [],
    stateMutability: 'payable',
  },
  { type: 'function', inputs: [], name: 'deposit', outputs: [], stateMutability: 'payable' },
  { type: 'function', inputs: [], name: 'entryPoint', outputs: [{ name: '', internalType: 'contract IEntryPoint', type: 'address' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'getDeposit', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'owner', outputs: [{ name: '', internalType: 'address', type: 'address' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'mode', internalType: 'enum IPaymaster.PostOpMode', type: 'uint8' },
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'actualGasCost', internalType: 'uint256', type: 'uint256' },
      { name: 'actualUserOpFeePerGas', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'postOp',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [], name: 'renounceOwnership', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [{ name: 'newOwner', internalType: 'address', type: 'address' }],
    name: 'transferOwnership',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'function', inputs: [], name: 'unlockStake', outputs: [], stateMutability: 'nonpayable' },
  {
    type: 'function',
    inputs: [
      {
        name: 'userOp',
        internalType: 'struct PackedUserOperation',
        type: 'tuple',
        components: [
          { name: 'sender', internalType: 'address', type: 'address' },
          { name: 'nonce', internalType: 'uint256', type: 'uint256' },
          { name: 'initCode', internalType: 'bytes', type: 'bytes' },
          { name: 'callData', internalType: 'bytes', type: 'bytes' },
          { name: 'accountGasLimits', internalType: 'bytes32', type: 'bytes32' },
          { name: 'preVerificationGas', internalType: 'uint256', type: 'uint256' },
          { name: 'gasFees', internalType: 'bytes32', type: 'bytes32' },
          { name: 'paymasterAndData', internalType: 'bytes', type: 'bytes' },
          { name: 'signature', internalType: 'bytes', type: 'bytes' },
        ],
      },
      { name: 'userOpHash', internalType: 'bytes32', type: 'bytes32' },
      { name: 'maxCost', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'validatePaymasterUserOp',
    outputs: [
      { name: 'context', internalType: 'bytes', type: 'bytes' },
      { name: 'validationData', internalType: 'uint256', type: 'uint256' },
    ],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [{ name: 'withdrawAddress', internalType: 'address payable', type: 'address' }],
    name: 'withdrawStake',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'withdrawAddress', internalType: 'address payable', type: 'address' },
      { name: 'amount', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'withdrawTo',
    outputs: [],
    stateMutability: 'nonpayable',
  },
  { type: 'receive', stateMutability: 'payable' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// PrivateERC20
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const privateErc20Abi = [
  { type: 'constructor', inputs: [{ name: 'initialSupply', internalType: 'uint256', type: 'uint256' }], stateMutability: 'nonpayable' },
  {
    type: 'error',
    inputs: [
      { name: 'spender', internalType: 'address', type: 'address' },
      { name: 'allowance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC20InsufficientAllowance',
  },
  {
    type: 'error',
    inputs: [
      { name: 'sender', internalType: 'address', type: 'address' },
      { name: 'balance', internalType: 'uint256', type: 'uint256' },
      { name: 'needed', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'ERC20InsufficientBalance',
  },
  { type: 'error', inputs: [{ name: 'approver', internalType: 'address', type: 'address' }], name: 'ERC20InvalidApprover' },
  { type: 'error', inputs: [{ name: 'receiver', internalType: 'address', type: 'address' }], name: 'ERC20InvalidReceiver' },
  { type: 'error', inputs: [{ name: 'sender', internalType: 'address', type: 'address' }], name: 'ERC20InvalidSender' },
  { type: 'error', inputs: [{ name: 'spender', internalType: 'address', type: 'address' }], name: 'ERC20InvalidSpender' },
  { type: 'error', inputs: [], name: 'InvalidMessageType' },
  { type: 'error', inputs: [], name: 'InvalidSignature' },
  {
    type: 'error',
    inputs: [
      { name: 'expectedSender', internalType: 'address', type: 'address' },
      { name: 'actualSender', internalType: 'address', type: 'address' },
    ],
    name: 'Unauthorized',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address', indexed: true },
      { name: 'spender', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Approval',
  },
  {
    type: 'event',
    anonymous: false,
    inputs: [
      { name: 'from', internalType: 'address', type: 'address', indexed: true },
      { name: 'to', internalType: 'address', type: 'address', indexed: true },
      { name: 'value', internalType: 'uint256', type: 'uint256', indexed: false },
    ],
    name: 'Transfer',
  },
  { type: 'function', inputs: [], name: 'DOMAIN_SEPARATOR', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'MESSAGE_TYPEHASH', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'owner', internalType: 'address', type: 'address' },
      { name: 'spender', internalType: 'address', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [
      { name: 'spender', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'content', internalType: 'string', type: 'string' },
      { name: 'timestamp', internalType: 'uint256', type: 'uint256' },
      { name: 'signature', internalType: 'bytes', type: 'bytes' },
      { name: 'approver', internalType: 'address', type: 'address' },
    ],
    name: 'approveMessage',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'decimals', outputs: [{ name: '', internalType: 'uint8', type: 'uint8' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'getDomainSeparator', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'getMessageTypeHash', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'pure' },
  { type: 'function', inputs: [{ name: 'amount', internalType: 'uint256', type: 'uint256' }], name: 'mint', outputs: [], stateMutability: 'nonpayable' },
  { type: 'function', inputs: [], name: 'name', outputs: [{ name: '', internalType: 'string', type: 'string' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [{ name: 'account', internalType: 'address', type: 'address' }],
    name: 'privateBalanceOf',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  { type: 'function', inputs: [], name: 'symbol', outputs: [{ name: '', internalType: 'string', type: 'string' }], stateMutability: 'view' },
  { type: 'function', inputs: [], name: 'totalSupply', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transfer',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    inputs: [
      { name: 'from', internalType: 'address', type: 'address' },
      { name: 'to', internalType: 'address', type: 'address' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'transferFrom',
    outputs: [{ name: '', internalType: 'bool', type: 'bool' }],
    stateMutability: 'nonpayable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Proxy
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const proxyAbi = [{ type: 'fallback', stateMutability: 'payable' }] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Receiver
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const receiverAbi = [
  { type: 'error', inputs: [], name: 'FnSelectorNotRecognized' },
  { type: 'fallback', stateMutability: 'payable' },
  { type: 'receive', stateMutability: 'payable' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// SafeCast
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const safeCastAbi = [
  {
    type: 'error',
    inputs: [
      { name: 'bits', internalType: 'uint8', type: 'uint8' },
      { name: 'value', internalType: 'int256', type: 'int256' },
    ],
    name: 'SafeCastOverflowedIntDowncast',
  },
  { type: 'error', inputs: [{ name: 'value', internalType: 'int256', type: 'int256' }], name: 'SafeCastOverflowedIntToUint' },
  {
    type: 'error',
    inputs: [
      { name: 'bits', internalType: 'uint8', type: 'uint8' },
      { name: 'value', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'SafeCastOverflowedUintDowncast',
  },
  { type: 'error', inputs: [{ name: 'value', internalType: 'uint256', type: 'uint256' }], name: 'SafeCastOverflowedUintToInt' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Strings
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const stringsAbi = [
  {
    type: 'error',
    inputs: [
      { name: 'value', internalType: 'uint256', type: 'uint256' },
      { name: 'length', internalType: 'uint256', type: 'uint256' },
    ],
    name: 'StringsInsufficientHexLength',
  },
  { type: 'error', inputs: [], name: 'StringsInvalidAddressFormat' },
  { type: 'error', inputs: [], name: 'StringsInvalidChar' },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UUPSUpgradeable
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const uupsUpgradeableAbi = [
  { type: 'error', inputs: [], name: 'UnauthorizedCallContext' },
  { type: 'error', inputs: [], name: 'UpgradeFailed' },
  { type: 'event', anonymous: false, inputs: [{ name: 'implementation', internalType: 'address', type: 'address', indexed: true }], name: 'Upgraded' },
  { type: 'function', inputs: [], name: 'proxiableUUID', outputs: [{ name: '', internalType: 'bytes32', type: 'bytes32' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [
      { name: 'newImplementation', internalType: 'address', type: 'address' },
      { name: 'data', internalType: 'bytes', type: 'bytes' },
    ],
    name: 'upgradeToAndCall',
    outputs: [],
    stateMutability: 'payable',
  },
] as const

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// UserOperationLib
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

export const userOperationLibAbi = [
  { type: 'function', inputs: [], name: 'PAYMASTER_DATA_OFFSET', outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }], stateMutability: 'view' },
  {
    type: 'function',
    inputs: [],
    name: 'PAYMASTER_POSTOP_GAS_OFFSET',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    inputs: [],
    name: 'PAYMASTER_VALIDATION_GAS_OFFSET',
    outputs: [{ name: '', internalType: 'uint256', type: 'uint256' }],
    stateMutability: 'view',
  },
] as const
