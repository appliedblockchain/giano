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
 */
contract AccountRegistry {
    /**
     * @notice Structure to store user information
     * @param publicKey The initial public key associated with the user
     * @param credentialId The ID of the credential associated with the user
     */
    struct User {
        Types.PublicKey publicKey;
        bytes credentialId;
    }
    
    // Mapping from account address to user info
    mapping(address => User) private users;
    
    // Mapping from credential ID to account address (to enforce one credential per account)
    mapping(bytes => address) private credentialToAccount;
    
    // Registry for deployed accounts
    mapping(address => bool) private registeredAccounts;
    
    // Factory for deploying accounts
    AbstractAccountFactory public immutable factory;
    
    // Salt for security
    bytes32 private immutable salt;
    
    /**
     * @notice Emitted when a new user is created
     * @param publicKey The initial public key associated with the user
     * @param account The address of the deployed Account contract
     */
    event UserCreated(Types.PublicKey publicKey, address indexed account);

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
    event CredentialRequestCreated(address indexed account, bytes indexed credentialId, uint8 role);

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
    error CredentialAlreadyLinked(bytes credentialId, address existingAccount);

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
     * @dev Sets up the factory reference and generates a unique salt for security
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
     * @notice Retrieves user information by account address
     * @param account The account address to look up
     * @return User struct containing the user's information
     */
    function getUser(address account) public view returns (User memory) {
        if (!registeredAccounts[account]) {
            revert UserNotFound();
        }
        return users[account];
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
     * @notice Creates a new user with an account and registers their initial credential
     * @dev Deploys a new Account contract and links the initial credential
     * @param credentialId The ID of the credential to associate with the user
     * @param publicKey The public key to associate with the user
     * @return accountAddress The address of the deployed account
     */
    function createUser(bytes calldata credentialId, Types.PublicKey calldata publicKey) external returns (address accountAddress) {
        // Verify credential isn't already linked to another account
        if (credentialToAccount[credentialId] != address(0)) {
            revert CredentialAlreadyLinked(credentialId, credentialToAccount[credentialId]);
        }
        
        // Call the factory to deploy a new Account contract
        accountAddress = factory.deployAccount(credentialId, publicKey, address(this));
        
        // Register the user and account
        users[accountAddress] = User(publicKey, credentialId);
        registeredAccounts[accountAddress] = true;
        
        // Link the initial admin credential
        credentialToAccount[credentialId] = accountAddress;
        
        emit UserCreated(publicKey, accountAddress);
        emit CredentialLinked(credentialId, accountAddress);
        
        return accountAddress;
    }
    
    /**
     * @notice Requests adding a new credential to an account
     * @dev Verifies the account exists and the credential isn't already linked
     * @param credentialId The ID of the credential to add
     * @param account The account address to add the credential to
     * @param publicKey The public key to add
     * @param role The role to assign to the credential
     */
    function requestAddCredential(
        bytes calldata credentialId,
        address account,
        Types.PublicKey calldata publicKey,
        uint8 role
    ) external {
        // Verify the account exists
        if (!registeredAccounts[account]) {
            revert AccountNotRegistered(account);
        }
        
        // Check if credential is already linked to an account
        address linkedAccount = credentialToAccount[credentialId];
        
        if (linkedAccount != address(0)) {
            revert CredentialAlreadyLinked(credentialId, linkedAccount);
        }
        
        // Create request in the account contract
        Account accountContract = Account(payable(account));
        accountContract.requestAddCredential(credentialId, publicKey, Account.Role(role));
        
        emit CredentialRequestCreated(account, credentialId, role);
    }
    
    /**
     * @notice Called by an account when a credential request is approved
     * @dev Links the credential to the calling account in the registry
     * @param credentialId The ID of the credential that was added
     */
    function notifyCredentialAdded(bytes calldata credentialId) public onlyRegisteredAccount {
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