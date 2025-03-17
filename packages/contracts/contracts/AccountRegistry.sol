// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';
import {Account} from './Account.sol';
import {AbstractAccountFactory} from './AbstractAccountFactory.sol';

/**
 * @title AccountRegistry
 * @author Giano Team
 * @notice Registry that tracks which credentials are linked to which Account contracts
 * @dev This contract prevents credentials from being linked to more than one Account
 * and acts as the main entrypoint for account creation and management.
 * It auto-generates unique IDs for new users based on their public keys.
 */
contract AccountRegistry {
    /**
     * @notice Structure to store user information
     * @param id Unique identifier for the user
     * @param publicKey The initial public key associated with the user
     * @param credentialId The ID of the credential associated with the user
     * @param account The address of the user's Account contract
     */
    struct User {
        uint256 id;
        Types.PublicKey publicKey;
        bytes credentialId;
        address account;
    }

    mapping(bytes => User) private bytesUser;

    // Mapping from user ID to user info
    mapping(uint256 => User) private users;
    
    // Mapping from credential ID to account address (to enforce one credential per account)
    mapping(bytes => address) private credentialToAccount;
    
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
     * @notice Emitted when a credential is linked to an account
     * @param credentialId The ID of the linked credential
     * @param account The address of the account the credential is linked to
     */
    event CredentialLinked(bytes indexed credentialId, address indexed account);

    /**
     * @notice Emitted when a credential is unlinked from an account
     * @param credentialId The ID of the unlinked credential
     * @param account The address of the account the credential was unlinked from
     */
    event CredentialUnlinked(bytes indexed credentialId, address indexed account);

    /**
     * @notice Emitted when a credential request is created
     * @param account The address of the account for which the credential is requested
     * @param credentialId The ID of the requested credential
     * @param role The role requested for the credential (0=NONE, 1=EXECUTOR, 2=ADMIN)
     */
    event AddCredentialRequestCreated(address indexed account, bytes indexed credentialId, uint8 role);
    
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
     * @notice Error thrown when attempting to link a credential that's already linked to another account
     * @param credentialId The ID of the already linked credential
     * @param existingAccount The address of the account the credential is already linked to
     */
    error CredentialAlreadyUnlinked(bytes credentialId, address existingAccount);

    /**
     * @notice Error thrown when an unauthorized address attempts an operation
     * @param caller The address of the unauthorized caller
     */
    error Unauthorized(address caller);

    /**
     * @notice Error thrown when a credential operation is attempted on a non-existent credential
     * @param credentialId The non-existent credential
     */
    error CredentialNotFound(bytes credentialId);

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
     * @notice Checks if a credential is already linked to an account
     * @param credentialId The ID of the credential to check
     * @return isLinked Boolean indicating whether the credential is linked
     * @return linkedAccount The address of the account the credential is linked to (if any)
     */
    function isCredentialLinked(bytes calldata credentialId) public view returns (bool, address) {
        address linkedAccount = credentialToAccount[credentialId];
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
     * @notice Creates a new user with an account and registers their initial credential
     * @dev Deploys a new Account contract and links the initial credential
     * @param credentialId The ID of the credential to associate with the user
     * @param publicKey The public key to associate with the user
     * @return userId The auto-generated unique user ID
     * @return accountAddress The address of the deployed account
     */
    function createUser(bytes calldata credentialId, Types.PublicKey calldata publicKey) external returns (uint256 userId, address accountAddress) {
        // Generate a unique, non-sequential user ID
        userId = _generateUserId(publicKey);
        
        // Verify user doesn't already exist (extremely unlikely but check anyway)
        if (users[userId].account != address(0)) {
            revert UserAlreadyExists(userId);
        }
        
        // Verify credential isn't already linked to another account
        if (credentialToAccount[credentialId] != address(0)) {
            revert CredentialAlreadyUnlinked(credentialId, credentialToAccount[credentialId]);
        }
        
        // Call the factory to deploy a new Account contract
        accountAddress = factory.deployAccount(credentialId, publicKey, address(this));
        
        // Register the user and account
        users[userId] = User(userId, publicKey, credentialId, accountAddress);
        registeredAccounts[accountAddress] = true;
        accountToUserId[accountAddress] = userId;
        
        // Link the initial admin credential
        credentialToAccount[credentialId] = accountAddress;
        
        emit UserCreated(userId, publicKey, accountAddress);
        emit CredentialLinked(credentialId, accountAddress);
        
        return (userId, accountAddress);
    }
    
    /**
     * @notice Requests adding a new credential to an account
     * @dev Verifies the account exists and the credential isn't already linked
     * @param credentialId The ID of the credential to add
     * @param account The account address to add the credential to
     * @param publicKey The public key to add
     * @param role The role to assign to the credential
     * @return requestId The ID of the created request
     */
    function requestAddCredential(
        bytes calldata credentialId,
        address account,
        Types.PublicKey calldata publicKey,
        uint8 role
    ) external returns (bytes32) {
        // Verify the account exists
        uint256 userId = accountToUserId[account];
        if (userId == 0 || !registeredAccounts[account]) {
            revert AccountNotRegistered(account);
        }
        
        // Check if credential is already linked to an account
        address linkedAccount = credentialToAccount[credentialId];
        
        if (linkedAccount != address(0)) {
            revert CredentialAlreadyUnlinked(credentialId, linkedAccount);
        }
        
        // Create request in the account contract
        Account accountContract = Account(payable(account));
        bytes32 requestId = accountContract.requestAddCredential(credentialId, publicKey, Account.Role(role));
        
        emit AddCredentialRequestCreated(account, credentialId, role);
        
        return requestId;
    }
    
    /**
     * @notice Called by an account when a credential request is approved
     * @dev Links the credential to the calling account in the registry
     * @param credentialId The ID of the credential that was added
     */
    function notifyKeyAdded(bytes calldata credentialId) public onlyRegisteredAccount {
        credentialToAccount[credentialId] = msg.sender;
        
        emit CredentialLinked(credentialId, msg.sender);
    }
    
    /**
     * @notice Called by an account when a credential is removed
     * @dev Removes the credential-account link from the registry
     * @param credentialId The ID of the credential that was removed
     */
    function notifyCredentialRemoved(bytes calldata credentialId) public onlyRegisteredAccount {
        // Verify the credential was linked to this account
        if (credentialToAccount[credentialId] != msg.sender) {
            revert CredentialNotFound(credentialId);
        }
        
        address account = credentialToAccount[credentialId];
        delete credentialToAccount[credentialId];
        
        emit CredentialUnlinked(credentialId, account);
    }
} 