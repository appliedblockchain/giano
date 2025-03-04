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
    
    // Mapping from account address to user ID
    mapping(address => uint256) private accountToUserId;
    
    // Registry for deployed accounts
    mapping(address => bool) private registeredAccounts;
    
    // Factory for deploying accounts
    AbstractAccountFactory public immutable factory;
    
    // Salt for ID generation
    bytes32 private immutable salt;
    
    event UserCreated(uint256 indexed userId, Types.PublicKey publicKey, address account);
    event KeyLinked(bytes32 indexed keyHash, address indexed account);
    event KeyRequestCreated(address indexed account, bytes32 indexed keyHash, uint8 role);
    
    error UserAlreadyExists(uint256 id);
    error AccountNotRegistered(address account);
    error KeyAlreadyLinked(bytes32 keyHash, address existingAccount);
    error Unauthorized(address caller);
    error KeyNotFound(bytes32 keyHash);
    error UserNotFound();
    
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
     * @dev Get user ID by account address
     */
    function getUserIdByAccount(address account) public view returns (uint256) {
        uint256 userId = accountToUserId[account];
        if (userId == 0 && !registeredAccounts[account]) {
            revert UserNotFound();
        }
        return userId;
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
     * @dev Generate a unique user ID from a public key
     * @param publicKey The public key to use for ID generation
     * @return A unique, non-sequential user ID
     */
    function _generateUserId(Types.PublicKey memory publicKey) internal view returns (uint256) {
        // Generate a unique ID using a combination of inputs
        // We add 1 to ensure the ID is never zero (which we use as an uninitialized value)
        return uint256(keccak256(abi.encodePacked(
            salt,
            publicKey.x,
            publicKey.y,
            block.timestamp,
            block.prevrandao
        )));
    }
    
    /**
     * @dev Create a new user with an account and register their initial key
     * @param publicKey The public key to associate with the user
     * @return userId The auto-generated unique user ID
     * @return accountAddress The address of the deployed account
     */
    function createUser(Types.PublicKey calldata publicKey) external returns (uint256 userId, address accountAddress) {
        // Generate a unique, non-sequential user ID
        userId = _generateUserId(publicKey);
        
        // Verify user doesn't already exist (extremely unlikely but check anyway)
        if (users[userId].account != address(0)) {
            revert UserAlreadyExists(userId);
        }
        
        // Verify key isn't already linked to another account
        bytes32 keyHash = _getKeyHash(publicKey);
        if (keyToAccount[keyHash] != address(0)) {
            revert KeyAlreadyLinked(keyHash, keyToAccount[keyHash]);
        }
        
        // Call the factory to deploy a new Account contract
        accountAddress = factory.deployAccount(publicKey, address(this));
        
        // Register the user and account
        users[userId] = User(userId, publicKey, accountAddress);
        registeredAccounts[accountAddress] = true;
        accountToUserId[accountAddress] = userId;
        
        // Link the initial admin key
        keyToAccount[keyHash] = accountAddress;
        
        emit UserCreated(userId, publicKey, accountAddress);
        emit KeyLinked(keyHash, accountAddress);
        
        return (userId, accountAddress);
    }
    
    /**
     * @dev Request to add a new key to an account
     * @param account The account address to add the key to
     * @param publicKey The public key to add
     * @param role The role to assign to the key
     */
    function requestAddKey(
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
        bytes32 keyHash = _getKeyHash(publicKey);
        address linkedAccount = keyToAccount[keyHash];
        
        if (linkedAccount != address(0)) {
            revert KeyAlreadyLinked(keyHash, linkedAccount);
        }
        
        // Create request in the account contract
        Account accountContract = Account(payable(account));
        bytes32 requestId = accountContract.requestAddKey(publicKey, Account.Role(role));
        
        emit KeyRequestCreated(account, keyHash, role);
        
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