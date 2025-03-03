// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';
import {Account} from './Account.sol';
import {AbstractAccountFactory} from './AbstractAccountFactory.sol';

/**
 * @title AccountRegistry
 * @dev Registry that tracks which keys are linked to which Account contracts
 * and prevents keys from being linked to more than one Account.
 * Acts as the main entrypoint for account creation and management.
 */
contract AccountRegistry {
    struct User {
        uint256 id;
        Types.PublicKey publicKey;
        address account;
    }

    // Mapping from user ID to user info
    mapping(uint256 => User) private users;
    
    // Mapping from public key hash to account address (to enforce one key per account)
    mapping(bytes32 => address) private keyToAccount;
    
    // Registry for deployed accounts
    mapping(address => bool) private registeredAccounts;
    
    // Factory for deploying accounts
    AbstractAccountFactory public immutable factory;
    
    event UserCreated(uint256 indexed userId, Types.PublicKey publicKey, address account);
    event KeyLinked(bytes32 indexed keyHash, address indexed account);
    event KeyRequestCreated(address indexed account, bytes32 indexed keyHash, uint8 role);
    
    error UserAlreadyExists(uint256 id);
    error AccountNotRegistered(address account);
    error KeyAlreadyLinked(bytes32 keyHash, address existingAccount);
    error Unauthorized(address caller);
    error KeyNotFound(bytes32 keyHash);
    
    constructor(address _factory) {
        factory = AbstractAccountFactory(_factory);
    }
    
    modifier onlyRegisteredAccount() {
        if (!registeredAccounts[msg.sender]) {
            revert AccountNotRegistered(msg.sender);
        }
        _;
    }
    
    /**
     * @dev Get user information by ID
     */
    function getUser(uint256 id) public view returns (User memory) {
        return users[id];
    }
    
    /**
     * @dev Check if a key is already linked to an account
     */
    function isKeyLinked(Types.PublicKey calldata publicKey) public view returns (bool, address) {
        bytes32 keyHash = _getKeyHash(publicKey);
        address linkedAccount = keyToAccount[keyHash];
        return (linkedAccount != address(0), linkedAccount);
    }
    
    /**
     * @dev Create a new user with an account and register their initial key
     * @param id The user ID
     * @param publicKey The public key to associate with the user
     */
    function createUser(uint256 id, Types.PublicKey calldata publicKey) external {
        // Verify user doesn't already exist
        if (users[id].account != address(0)) {
            revert UserAlreadyExists(id);
        }
        
        // Verify key isn't already linked to another account
        bytes32 keyHash = _getKeyHash(publicKey);
        if (keyToAccount[keyHash] != address(0)) {
            revert KeyAlreadyLinked(keyHash, keyToAccount[keyHash]);
        }
        
        // Call the factory to deploy a new Account contract
        address account = factory.deployAccount(publicKey, address(this));
        
        // Register the user and account
        users[id] = User(id, publicKey, account);
        registeredAccounts[account] = true;
        
        // Link the initial admin key
        keyToAccount[keyHash] = account;
        
        emit UserCreated(id, publicKey, account);
        emit KeyLinked(keyHash, account);
    }
    
    /**
     * @dev Request to add a new key to an account
     * @notice This can only be called by a user with an existing account
     */
    function requestAddKey(
        uint256 userId,
        Types.PublicKey calldata publicKey, 
        uint8 role
    ) external returns (bytes32) {
        // Verify caller is associated with the user ID
        User memory user = users[userId];
        if (user.account == address(0)) {
            revert Unauthorized(msg.sender);
        }
        
        // Check if key is already linked
        bytes32 keyHash = _getKeyHash(publicKey);
        address linkedAccount = keyToAccount[keyHash];
        
        if (linkedAccount != address(0)) {
            revert KeyAlreadyLinked(keyHash, linkedAccount);
        }
        
        // Create request in the account contract
        Account account = Account(payable(user.account));
        bytes32 requestId = account.requestAddKey(publicKey, Account.Role(role));
        
        emit KeyRequestCreated(user.account, keyHash, role);
        
        return requestId;
    }
    
    /**
     * @dev Called by an account when a key request is approved
     * @notice This can only be called by a registered account
     */
    function notifyKeyAdded(Types.PublicKey calldata publicKey) public onlyRegisteredAccount {
        bytes32 keyHash = _getKeyHash(publicKey);
        keyToAccount[keyHash] = msg.sender;
        
        emit KeyLinked(keyHash, msg.sender);
    }
    
    /**
     * @dev Called by an account when a key is removed
     * @notice This can only be called by a registered account
     */
    function notifyKeyRemoved(Types.PublicKey calldata publicKey) public onlyRegisteredAccount {
        bytes32 keyHash = _getKeyHash(publicKey);
        
        // Verify the key was linked to this account
        if (keyToAccount[keyHash] != msg.sender) {
            revert KeyNotFound(keyHash);
        }
        
        delete keyToAccount[keyHash];
    }
    
    /**
     * @dev Get the hash of a public key
     */
    function _getKeyHash(Types.PublicKey memory _publicKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(_publicKey.x, _publicKey.y));
    }
} 