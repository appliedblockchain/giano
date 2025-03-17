// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';
import {Account} from './Account.sol';
import {AbstractAccountFactory} from './AbstractAccountFactory.sol';

/**
 * @title AccountRegistry
 * @author Giano Team
 * @notice Registry that tracks which keys are linked to which Account contracts
 * @dev This contract prevents keys from being linked to more than one Account
 * and acts as the main entrypoint for account creation and management.
 * It auto-generates unique IDs for new users based on their public keys.
 */
contract AccountRegistry {
    /**
     * @notice Structure to store user information
     * @param id Unique identifier for the user
     * @param publicKey The initial public key associated with the user
     * @param keyId The ID of the key associated with the user
     * @param account The address of the user's Account contract
     */
    struct User {
        uint256 id;
        Types.PublicKey publicKey;
        bytes keyId;
        address account;
    }

    mapping(bytes => User) private bytesUser;

    // Mapping from user ID to user info
    mapping(uint256 => User) private users;
    
    // Mapping from key ID to account address (to enforce one key per account)
    mapping(bytes => address) private keyToAccount;
    
    // Mapping from account address to user ID
    mapping(address => uint256) private accountToUserId;
    
    // Registry for deployed accounts
    mapping(address => bool) private registeredAccounts;
    
    // Factory for deploying accounts
    AbstractAccountFactory public immutable factory;
    
    // Salt for ID generation
    bytes32 private immutable salt;
    
    /**
     * @notice Emitted when a new user is created
     * @param userId The unique ID of the created user
     * @param publicKey The initial public key associated with the user
     * @param account The address of the deployed Account contract
     */
    event UserCreated(uint256 indexed userId, Types.PublicKey publicKey, address account);

    /**
     * @notice Emitted when a key is linked to an account
     * @param keyHash The hash of the linked public key
     * @param account The address of the account the key is linked to
     */
    event KeyLinked(bytes32 indexed keyHash, address indexed account);

    /**
     * @notice Emitted when a key is unlinked from an account
     * @param keyHash The hash of the unlinked public key
     * @param account The address of the account the key was unlinked from
     */
    event KeyUnlinked(bytes32 indexed keyHash, address indexed account);

    /**
     * @notice Emitted when a key request is created
     * @param account The address of the account for which the key is requested
     * @param keyHash The hash of the requested public key
     * @param role The role requested for the key (0=NONE, 1=EXECUTOR, 2=ADMIN)
     */
    event KeyRequestCreated(address indexed account, bytes32 indexed keyHash, uint8 role);
    
    /**
     * @notice Error thrown when attempting to create a user with an ID that already exists
     * @param id The ID that already exists
     */
    error UserAlreadyExists(uint256 id);

    /**
     * @notice Error thrown when an operation is attempted on an unregistered account
     * @param account The address of the unregistered account
     */
    error AccountNotRegistered(address account);

    /**
     * @notice Error thrown when attempting to link a key that's already linked to another account
     * @param keyHash The hash of the already linked key
     * @param existingAccount The address of the account the key is already linked to
     */
    error KeyAlreadyLinked(bytes32 keyHash, address existingAccount);

    /**
     * @notice Error thrown when an unauthorized address attempts an operation
     * @param caller The address of the unauthorized caller
     */
    error Unauthorized(address caller);

    /**
     * @notice Error thrown when a key operation is attempted on a non-existent key
     * @param keyHash The hash of the non-existent key
     */
    error KeyNotFound(bytes32 keyHash);

    /**
     * @notice Error thrown when a user lookup fails
     */
    error UserNotFound();
    
    /**
     * @notice Initializes the AccountRegistry with a factory address
     * @dev Sets up the factory reference and generates a unique salt for ID creation
     * @param _factory The address of the AbstractAccountFactory contract
     */
    constructor(address _factory) {
        factory = AbstractAccountFactory(_factory);
        // Generate a unique salt based on deployment parameters
        salt = keccak256(abi.encodePacked(
            block.timestamp, 
            block.prevrandao, 
            address(this),
            msg.sender
        ));
    }
    
    /**
     * @notice Ensures the caller is a registered account
     */
    modifier onlyRegisteredAccount() {
        if (!registeredAccounts[msg.sender]) {
            revert AccountNotRegistered(msg.sender);
        }
        _;
    }
    
    /**
     * @notice Retrieves user information by ID
     * @param id The user ID to look up
     * @return User struct containing the user's information
     */
    function getUser(uint256 id) public view returns (User memory) {
        return users[id];
    }
    
    /**
     * @notice Retrieves a user ID by account address
     * @param account The account address to look up
     * @return The user ID associated with the account
     * @dev Reverts if the account is not registered
     */
    function getUserIdByAccount(address account) public view returns (uint256) {
        uint256 userId = accountToUserId[account];
        if (userId == 0 && !registeredAccounts[account]) {
            revert UserNotFound();
        }
        return userId;
    }
    
    /**
     * @notice Checks if a key is already linked to an account
     * @param keyId The ID of the key to check
     * @return isLinked Boolean indicating whether the key is linked
     * @return linkedAccount The address of the account the key is linked to (if any)
     */
    function isKeyLinked(bytes calldata keyId) public view returns (bool, address) {
        address linkedAccount = keyToAccount[keyId];
        return (linkedAccount != address(0), linkedAccount);
    }
    
    /**
     * @notice Generates a unique user ID from a public key
     * @dev Uses multiple sources of entropy to create a unique, non-sequential ID
     * @param publicKey The public key to use for ID generation
     * @return A unique, non-sequential user ID
     */
    function _generateUserId(Types.PublicKey memory publicKey) internal view returns (uint256) {
        // Generate a unique ID using a combination of inputs
        // We add 1 to ensure the ID is never zero (which we use as an uninitialized value)
        uint256 rawId = uint256(keccak256(abi.encodePacked(
            salt,
            publicKey.x,
            publicKey.y,
            block.timestamp,
            block.prevrandao
        )));
        
        return rawId == 0 ? 1 : rawId;
    }
    
    /**
     * @notice Creates a new user with an account and registers their initial key
     * @dev Deploys a new Account contract and links the initial key
     * @param keyId The ID of the key to associate with the user
     * @param publicKey The public key to associate with the user
     * @return userId The auto-generated unique user ID
     * @return accountAddress The address of the deployed account
     */
    function createUser(bytes calldata keyId, Types.PublicKey calldata publicKey) external returns (uint256 userId, address accountAddress) {
        // Generate a unique, non-sequential user ID
        userId = _generateUserId(publicKey);
        
        // Verify user doesn't already exist (extremely unlikely but check anyway)
        if (users[userId].account != address(0)) {
            revert UserAlreadyExists(userId);
        }
        
        // Verify key isn't already linked to another account
        if (keyToAccount[keyId] != address(0)) {
            revert KeyAlreadyLinked(keccak256(keyId), keyToAccount[keyId]);
        }
        
        // Call the factory to deploy a new Account contract
        accountAddress = factory.deployAccount(keyId, publicKey, address(this));
        
        // Register the user and account
        users[userId] = User(userId, publicKey, keyId, accountAddress);
        registeredAccounts[accountAddress] = true;
        accountToUserId[accountAddress] = userId;
        
        // Link the initial admin key
        keyToAccount[keyId] = accountAddress;
        
        emit UserCreated(userId, publicKey, accountAddress);
        emit KeyLinked(keccak256(keyId), accountAddress);
        
        return (userId, accountAddress);
    }
    
    /**
     * @notice Requests adding a new key to an account
     * @dev Verifies the account exists and the key isn't already linked
     * @param keyId The ID of the key to add
     * @param account The account address to add the key to
     * @param publicKey The public key to add
     * @param role The role to assign to the key
     * @return requestId The ID of the created request
     */
    function requestAddKey(
        bytes calldata keyId,
        address account,
        Types.PublicKey calldata publicKey,
        uint8 role
    ) external returns (bytes32) {
        // Verify the account exists
        uint256 userId = accountToUserId[account];
        if (userId == 0 || !registeredAccounts[account]) {
            revert AccountNotRegistered(account);
        }
        
        // Check if key is already linked to an account
        address linkedAccount = keyToAccount[keyId];
        
        if (linkedAccount != address(0)) {
            revert KeyAlreadyLinked(keccak256(keyId), linkedAccount);
        }
        
        // Create request in the account contract
        Account accountContract = Account(payable(account));
        bytes32 requestId = accountContract.requestAddKey(keyId, publicKey, Account.Role(role));
        
        emit KeyRequestCreated(account, keccak256(keyId), role);
        
        return requestId;
    }
    
    /**
     * @notice Called by an account when a key request is approved
     * @dev Links the key to the calling account in the registry
     * @param keyId The ID of the key that was added
     */
    function notifyKeyAdded(bytes calldata keyId) public onlyRegisteredAccount {
        keyToAccount[keyId] = msg.sender;
        
        emit KeyLinked(keccak256(keyId), msg.sender);
    }
    
    /**
     * @notice Called by an account when a key is removed
     * @dev Removes the key-account link from the registry
     * @param keyId The ID of the key that was removed
     */
    function notifyKeyRemoved(bytes calldata keyId) public onlyRegisteredAccount {
        // Verify the key was linked to this account
        if (keyToAccount[keyId] != msg.sender) {
            revert KeyNotFound(keccak256(keyId));
        }
        
        address account = keyToAccount[keyId];
        delete keyToAccount[keyId];
        
        emit KeyUnlinked(keccak256(keyId), account);
    }
} 