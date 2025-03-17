// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {WebAuthn} from './WebAuthn.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {IERC721Receiver} from '@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol';
import {IERC1155Receiver} from '@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol';
import {Types} from './Types.sol';
import {AccountRegistry} from './AccountRegistry.sol';

/**
 * @title Account
 * @author Giano Team
 * @notice A smart wallet implementation that allows execution of arbitrary functions with multiple signers having different roles
 * @dev This contract implements WebAuthn signature verification and supports multiple credentials with different permissions
 */
contract Account is ReentrancyGuard, IERC1271, IERC721Receiver, IERC1155Receiver {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;

    /**
     * @notice Error thrown when signature validation fails
     * @param reason Human-readable reason for the failure
     */
    error InvalidSignature(string reason);

    /**
     * @notice Error thrown when a credential attempts an operation it is not authorized for
     * @param credentialId The credential ID of the unauthorized credential
     * @param requiredRole The minimum role required for the operation
     */
    error NotAuthorized(bytes credentialId, Role requiredRole);

    /**
     * @notice Error thrown when an operation is attempted on a non-existent credential
     * @param credentialId The credential ID of the non-existent credential
     */
    error CredentialDoesNotExist(bytes credentialId);

    /**
     * @notice Error thrown when an operation is attempted on a non-existent request
     * @param requestId The ID of the non-existent request
     */
    error RequestDoesNotExist(bytes32 requestId);

    /**
     * @notice Error thrown when attempting to add a credential that already exists
     * @param credentialId The credential ID of the existing credential
     */
    error CredentialAlreadyExists(bytes credentialId);

    /**
     * @notice Error thrown when an admin operation type doesn't match the expected type
     * @param expected The expected operation type
     * @param received The received operation type
     */
    error InvalidOperation(AdminOperation expected, AdminOperation received);

    /**
     * @notice Error thrown when a nonce doesn't match the expected value
     * @param expected The expected nonce
     * @param received The received nonce
     */
    error InvalidNonce(uint256 expected, uint256 received);

    /**
     * @notice Error thrown when invalid operation data is provided
     */
    error InvalidOperationData();

    /**
     * @notice Error thrown when an unauthorized address attempts to add credentials
     */
    error OnlyRegistryCanAddCredentials();

    /**
     * @notice Error thrown when a standard signature validation fails
     */
    error InvalidExecutorSignature();

    /**
     * @notice Error thrown when an admin signature validation fails
     */
    error InvalidAdminSignature();

    /**
     * @notice Error thrown when attempting to remove or downgrade the last admin credential
     */
    error LastAdminCredential();

    /**
     * @notice Error thrown when attempting operations while the account is paused
     * @param until The timestamp until which the account is paused
     */
    error AccountIsPaused(uint256 until);

    /**
     * @notice Role levels for credentials associated with the account
     * @dev Higher role levels include the permissions of lower levels
     */
    enum Role {
        NONE, // Key doesn't exist or has no permissions
        EXECUTOR,
        ADMIN
    }

    /**
     * @notice Structure to store information about a credential
     * @param credentialId The credential identifier
     * @param publicKey The public key
     * @param role The role assigned to the credential
     */
    struct CredentialInfo {
        bytes credentialId;
        Types.PublicKey publicKey;
        Role role;
    }

    /**
     * @notice Structure to store information about a credential request
     * @param credentialId The credential identifier
     * @param publicKey The public key being requested
     * @param requestedRole The role being requested for the credential
     * @param exists Whether the request exists
     */
    struct KeyRequest {
        bytes credentialId;
        Types.PublicKey publicKey;
        Role requestedRole;
        bool exists;
    }

    /**
     * @notice Types of administrative operations that can be performed
     */
    enum AdminOperation {
        APPROVE_CREDENTIAL_REQUEST,
        REJECT_CREDENTIAL_REQUEST,
        REMOVE_CREDENTIAL,
        CHANGE_CREDENTIAL_ROLE,
        PAUSE_ACCOUNT,
        UNPAUSE_ACCOUNT
    }

    /**
     * @notice Structure for administrative actions
     * @param operation The type of admin operation
     * @param operationData The encoded data for the operation
     * @param nonce The nonce for the operation to prevent replay attacks
     * @param signature The signature authorizing the operation
     */
    struct AdminAction {
        AdminOperation operation;
        bytes operationData;
        uint256 nonce;
        bytes signature;
    }

    /**
     * @notice Structure for batch execution
     * @param calls Array of call parameters to execute in sequence
     * @param signature The signature authorizing all calls
     */
    struct BatchCall {
        Types.Call[] calls;
        bytes signature;
    }

    /**
     * @notice Emitted when a credential addition is requested
     * @param requestId The ID of the created request
     * @param publicKey The public key requested to be added
     * @param requestedRole The requested role for the credential
     */
    event AddCredentialRequested(bytes32 indexed requestId, Types.PublicKey publicKey, Role requestedRole);

    /**
     * @notice Emitted when a credential request is approved
     * @param requestId The ID of the approved request
     * @param publicKey The public key that was approved
     * @param role The assigned role for the credential
     */
    event KeyRequestApproved(bytes32 indexed requestId, Types.PublicKey publicKey, Role role);

    /**
     * @notice Emitted when a credential request is rejected
     * @param requestId The ID of the rejected request
     */
    event KeyRequestRejected(bytes32 indexed requestId);

    /**
     * @notice Emitted when a credential is added to the account
     * @param publicKey The public key that was added
     * @param role The assigned role for the credential
     */
    event KeyAdded(Types.PublicKey publicKey, Role role);

    /**
     * @notice Emitted when a credential is removed from the account
     * @param publicKey The public key that was removed
     */
    event KeyRemoved(Types.PublicKey publicKey);

    /**
     * @notice Emitted when a credential's role is changed
     * @param publicKey The public key whose role was changed
     * @param newRole The new role assigned to the credential
     */
    event KeyRoleChanged(Types.PublicKey publicKey, Role newRole);

    /**
     * @notice Emitted when an administrative action is executed
     * @param operation The type of operation that was executed
     * @param nonce The nonce used for the operation
     */
    event AdminActionExecuted(AdminOperation indexed operation, uint256 nonce);

    /**
     * @notice Emitted when an operation is executed
     * @param nonce The nonce used for the operation
     * @param target The target address of the call
     * @param value The value sent with the call
     * @param data The calldata sent with the call
     */
    event Executed(uint256 indexed nonce, address indexed target, uint256 value, bytes data);

    /**
     * @notice Emitted when the account is paused
     * @param until The timestamp until which the account is paused (0 for indefinite)
     */
    event AccountPaused(uint256 until);

    /**
     * @notice Emitted when the account is unpaused
     */
    event AccountUnpaused();

    mapping(bytes => CredentialInfo) private credentials;

    mapping(bytes32 => KeyRequest) private credentialRequests;

    // Storage optimization: Pack related uint values into a single storage slot

    uint64 private requestNonce;
    uint64 private adminNonce;
    uint64 private currentNonce;
    uint64 private adminKeyCount;

    // Address of the registry contract
    address public immutable registry;

    uint256 private pausedUntil;

    /**
     * @notice Initializes the Account with an initial admin credential and registry
     * @dev Sets up the initial admin credential and registers the registry
     * @param _initialAdminKey The initial public key to be given admin role
     * @param _initialCredentialId The initial credential identifier for the admin credential
     * @param _registry The address of the AccountRegistry contract
     */
    constructor(Types.PublicKey memory _initialAdminKey, bytes memory _initialCredentialId, address _registry) {
        credentials[_initialCredentialId] = CredentialInfo({publicKey: _initialAdminKey, role: Role.ADMIN, credentialId: _initialCredentialId});
        registry = _registry;
        adminKeyCount = 1;

        emit KeyAdded(_initialAdminKey, Role.ADMIN);
    }

    /**
     * @notice Returns the expected challenge for a given call payload
     * @dev Used to verify signatures for execute calls
     * @param call The call parameters to generate the challenge against
     * @return The challenge hash for signature verification
     */
    function getChallenge(Types.Call calldata call) public view returns (bytes32) {
        return keccak256(bytes.concat(bytes20(address(this)), bytes32(uint256(currentNonce)), bytes20(call.target), bytes32(call.value), call.data));
    }

    /**
     * @notice Returns the expected challenge for an admin operation
     * @dev Used to verify signatures for admin operations
     * @param adminAction The admin action to generate the challenge against
     * @return The challenge hash for signature verification
     */
    function getAdminChallenge(AdminAction memory adminAction) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), adminAction.operation, adminAction.operationData, adminAction.nonce));
    }

    /**
     * @notice Computes the hash of a public key
     * @dev Used for efficiently storing and looking up credentials
     * @param _credentialId The credential identifier to hash
     * @return The keccak256 hash of the credential identifier
     */
    function _getKeyHash(bytes memory _credentialId) internal pure returns (bytes32) {
        return keccak256(_credentialId);
    }

    /**
     * @notice Checks if a credential exists and has at least the specified role
     * @dev Used to verify authorization for operations
     * @param _credentialId The credential identifier
     * @param _minimumRole The minimum role required
     * @return Boolean indicating whether the credential has the required role
     */
    function _hasRole(bytes memory _credentialId, Role _minimumRole) internal view returns (bool) {
        return uint8(credentials[_credentialId].role) >= uint8(_minimumRole);
    }

    /**
     * @notice Checks if a credential exists (has any role)
     * @dev Used to determine whether a credential has been registered
     * @param _credentialId The credential identifier
     * @return Boolean indicating whether the credential exists
     */
    function _credentialExists(bytes memory _credentialId) internal view returns (bool) {
        return credentials[_credentialId].role != Role.NONE;
    }

    /**
     * @notice Returns information about a specific credential
     * @param _credentialId The credential identifier
     * @return CredentialInfo struct containing the credential's information
     */
    function getCredentialInfo(bytes calldata _credentialId) external view returns (CredentialInfo memory) {
        return credentials[_credentialId];
    }

    /**
     * @notice Gets the current admin nonce
     * @dev Used to prevent replay attacks for admin operations
     * @return The current admin nonce
     */
    function getAdminNonce() external view returns (uint256) {
        return adminNonce;
    }

    /**
     * @notice Gets the current transaction nonce
     * @dev Used to prevent replay attacks for execute operations
     * @return The current transaction nonce
     */
    function getNonce() external view returns (uint256) {
        return currentNonce;
    }

    /**
     * @notice Gets the current admin credential count
     * @return The current number of admin credentials
     */
    function getAdminKeyCount() external view returns (uint256) {
        return adminKeyCount;
    }

    /**
     * @notice Verifies that a signature is valid
     * @dev Reverts if the signature verification fails
     * @param message The message that was signed
     * @param signature The signature to verify
     */
    modifier validSignature(bytes memory message, bytes calldata signature) {
        if (!_validateSignature(message, signature)) {
            revert InvalidExecutorSignature();
        }
        _;
    }

    /**
     * @notice Verifies that an admin operation is authorized
     * @dev Validates the operation type, signature, and nonce
     * @param expectedOperation The expected operation type
     * @param adminAction The admin action to validate
     */
    modifier onlyAdmin(AdminOperation expectedOperation, AdminAction memory adminAction) {
        if (adminAction.operation != expectedOperation) {
            revert InvalidOperation(expectedOperation, adminAction.operation);
        }

        bytes32 challenge = getAdminChallenge(adminAction);

        if (!_validateAdminSignature(bytes.concat(challenge), adminAction.signature)) {
            revert InvalidAdminSignature();
        }

        if (adminAction.nonce != adminNonce) {
            revert InvalidNonce(adminNonce, adminAction.nonce);
        }

        adminNonce++;

        emit AdminActionExecuted(adminAction.operation, adminAction.nonce);
        _;
    }

    /**
     * @notice Ensures the caller is the registry contract
     * @dev Used to restrict credential management functions to the registry
     */
    modifier onlyRegistry() {
        if (msg.sender != registry) {
            revert OnlyRegistryCanAddCredentials();
        }
        _;
    }

    /**
     * @notice Allows the account to receive ETH
     */
    receive() external payable {}

    /**
     * @notice Fallback function that allows the account to receive ETH
     */
    fallback() external payable {}

    /**
     * @notice Requests to add a new credential to the contract
     * @dev Can only be called by the registry
     * @param credentialId The credential identifier
     * @param publicKey The public key to add
     * @param role The requested role for the credential
     * @return requestId The ID of the created request
     */
    function requestAddCredential(bytes calldata credentialId, Types.PublicKey calldata publicKey, Role role) external onlyRegistry returns (bytes32 requestId) {
        if (credentials[credentialId].role != Role.NONE) {
            revert CredentialAlreadyExists(credentialId);
        }

        requestId = keccak256(abi.encodePacked(block.timestamp, msg.sender, credentialId));

        credentialRequests[requestId] = KeyRequest({credentialId: credentialId, publicKey: publicKey, requestedRole: role, exists: true});

        emit AddCredentialRequested(requestId, publicKey, role);

        return requestId;
    }

    /**
     * @notice Approves a credential addition request
     * @dev Can only be called by an admin and notifies the registry
     * @param requestId The ID of the request to approve
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function approveKeyRequest(bytes32 requestId, AdminAction memory adminAction) external onlyAdmin(AdminOperation.APPROVE_CREDENTIAL_REQUEST, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(requestId))) {
            revert InvalidOperationData();
        }

        KeyRequest memory request = credentialRequests[requestId];
        if (!request.exists) {
            revert RequestDoesNotExist(requestId);
        }

        credentials[request.credentialId] = CredentialInfo({publicKey: request.publicKey, role: request.requestedRole, credentialId: request.credentialId});

        if (request.requestedRole == Role.ADMIN) {
            adminKeyCount++;
        }

        delete credentialRequests[requestId];

        AccountRegistry(registry).notifyKeyAdded(request.credentialId);

        emit KeyRequestApproved(requestId, request.publicKey, request.requestedRole);
        emit KeyAdded(request.publicKey, request.requestedRole);
    }

    /**
     * @notice Rejects a credential addition request
     * @dev Can only be called by an admin
     * @param requestId The ID of the request to reject
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function rejectKeyRequest(bytes32 requestId, AdminAction memory adminAction) external onlyAdmin(AdminOperation.REJECT_CREDENTIAL_REQUEST, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(requestId))) {
            revert InvalidOperationData();
        }

        if (!credentialRequests[requestId].exists) {
            revert RequestDoesNotExist(requestId);
        }

        delete credentialRequests[requestId];

        emit KeyRequestRejected(requestId);
    }

    /**
     * @notice Removes an existing credential
     * @dev Can only be called by an admin and notifies the registry
     * @param credentialId The credential identifier
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function removeKey(bytes calldata credentialId, AdminAction memory adminAction) external onlyAdmin(AdminOperation.REMOVE_CREDENTIAL, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(credentialId))) {
            revert InvalidOperationData();
        }

        if (credentials[credentialId].role == Role.NONE) {
            revert CredentialDoesNotExist(credentialId);
        }

        if (credentials[credentialId].role == Role.ADMIN) {
            if (adminKeyCount <= 1) {
                revert LastAdminCredential();
            }
            adminKeyCount--;
        }

        Types.PublicKey memory publicKey = credentials[credentialId].publicKey;
        credentials[credentialId].role = Role.NONE;

        AccountRegistry(registry).notifyCredentialRemoved(credentialId);

        emit KeyRemoved(publicKey);
    }

    /**
     * @notice Changes the role of an existing credential
     * @dev Can only be called by an admin
     * @param credentialId The credential identifier
     * @param newRole The new role for the credential
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function changeKeyRole(
        bytes calldata credentialId,
        Role newRole,
        AdminAction memory adminAction
    ) external onlyAdmin(AdminOperation.CHANGE_CREDENTIAL_ROLE, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(credentialId, newRole))) {
            revert InvalidOperationData();
        }

        if (credentials[credentialId].role == Role.NONE) {
            revert CredentialDoesNotExist(credentialId);
        }

        if (credentials[credentialId].role == Role.ADMIN && newRole != Role.ADMIN) {
            if (adminKeyCount <= 1) {
                revert LastAdminCredential();
            }
            adminKeyCount--;
        } else if (credentials[credentialId].role != Role.ADMIN && newRole == Role.ADMIN) {
            adminKeyCount++;
        }

        Types.PublicKey memory publicKey = credentials[credentialId].publicKey;
        credentials[credentialId].role = newRole;

        emit KeyRoleChanged(publicKey, newRole);
    }

    /**
     * @notice Returns the expected challenge for a batch of calls
     * @dev Used to verify signatures for batch execute calls
     * @param calls The array of call parameters to generate the challenge against
     * @return The challenge hash for signature verification
     */
    function getBatchChallenge(Types.Call[] calldata calls) public view returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callHashes[i] = keccak256(abi.encode(calls[i].target, calls[i].value, calls[i].data));
        }
        return keccak256(abi.encode(address(this), currentNonce, callHashes));
    }

    /**
     * @notice Ensures the account is not paused
     * @dev Reverts if account is currently paused
     */
    modifier whenNotPaused() {
        if (pausedUntil > block.timestamp) {
            revert AccountIsPaused(pausedUntil);
        }
        _;
    }

    /**
     * @notice Executes an arbitrary call on a smart contract
     * @dev Requires a valid signature from a credential with EXECUTOR or ADMIN role
     * @param signed The parameters of the call to be executed
     */
    function execute(
        Types.SignedCall calldata signed
    ) external payable validSignature(bytes.concat(getChallenge(signed.call)), signed.signature) nonReentrant whenNotPaused {
        (bool success, bytes memory result) = signed.call.target.call{value: signed.call.value}(signed.call.data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        emit Executed(currentNonce, signed.call.target, signed.call.value, signed.call.data);
        currentNonce++;
    }

    /**
     * @notice Executes multiple calls in a single transaction
     * @dev Requires a valid signature from a credential with EXECUTOR or ADMIN role
     * @param batch The batch of calls to be executed with signature
     */
    function executeBatch(
        BatchCall calldata batch
    ) external payable validSignature(bytes.concat(getBatchChallenge(batch.calls)), batch.signature) nonReentrant whenNotPaused {
        uint256 callsLength = batch.calls.length;
        require(callsLength > 0, 'No calls to execute');

        for (uint256 i = 0; i < callsLength; i++) {
            Types.Call calldata currentCall = batch.calls[i];
            (bool success, bytes memory result) = currentCall.target.call{value: currentCall.value}(currentCall.data);
            if (!success) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }
        }

        emit Executed(currentNonce, address(0), 0, abi.encode(batch.calls));
        currentNonce++;
    }

    /**
     * @notice Validates a signature for an admin operation
     * @dev Checks if the signer has ADMIN role and verifies the WebAuthn signature
     * @param message The message that was signed
     * @param signature The signature to verify
     * @return Boolean indicating whether the signature is valid
     */
    function _validateAdminSignature(bytes memory message, bytes memory signature) private view returns (bool) {
        Types.Signature memory sig = abi.decode(signature, (Types.Signature));

        if (!_hasRole(sig.credentialId, Role.ADMIN)) {
            return false;
        }

        CredentialInfo memory credentialInfo = credentials[sig.credentialId];

        return
            WebAuthn.verifySignature({
                challenge: message,
                authenticatorData: sig.authenticatorData,
                requireUserVerification: false,
                clientDataJSON: sig.clientDataJSON,
                challengeLocation: sig.challengeLocation,
                responseTypeLocation: sig.responseTypeLocation,
                r: sig.r,
                s: sig.s,
                x: uint256(credentialInfo.publicKey.x),
                y: uint256(credentialInfo.publicKey.y)
            });
    }

    /**
     * @notice Validates a signature for an execute operation
     * @dev Checks if the signer has at least EXECUTOR role and verifies the WebAuthn signature
     * @param message The message that was signed
     * @param signature The signature to verify
     * @return Boolean indicating whether the signature is valid
     */
    function _validateSignature(bytes memory message, bytes calldata signature) private view returns (bool) {
        Types.Signature memory sig = abi.decode(signature, (Types.Signature));

        CredentialInfo memory credentialInfo = credentials[sig.credentialId];
        if (credentialInfo.role == Role.NONE) {
            return false;
        }

        return
            WebAuthn.verifySignature({
                challenge: message,
                authenticatorData: sig.authenticatorData,
                requireUserVerification: false,
                clientDataJSON: sig.clientDataJSON,
                challengeLocation: sig.challengeLocation,
                responseTypeLocation: sig.responseTypeLocation,
                r: sig.r,
                s: sig.s,
                x: uint256(credentialInfo.publicKey.x),
                y: uint256(credentialInfo.publicKey.y)
            });
    }

    /**
     * @notice Implements ERC-1271 signature verification
     * @dev Allows the account to be used with ERC-1271 compatible contracts
     * @param messageHash The hash of the message that was signed
     * @param signature The signature to verify
     * @return magicValue The magic value if the signature is valid, or 0xffffffff if invalid
     */
    function isValidSignature(bytes32 messageHash, bytes calldata signature) public view override returns (bytes4 magicValue) {
        if (_validateSignature(bytes.concat(messageHash), signature)) {
            return ERC1271_MAGICVALUE;
        }
        return 0xffffffff;
    }

    /**
     * @notice Handles the receipt of an ERC721 token
     * @dev Implements IERC721Receiver interface
     * @return The ERC721Receiver selector
     */
    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /**
     * @notice Handles the receipt of a single ERC1155 token
     * @dev Implements IERC1155Receiver interface
     * @return The ERC1155Receiver selector
     */
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    /**
     * @notice Handles the receipt of multiple ERC1155 tokens
     * @dev Implements IERC1155Receiver interface
     * @return The ERC1155BatchReceived selector
     */
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    /**
     * @notice Indicates which interfaces this contract supports
     * @dev Implements the ERC-165 standard
     * @param interfaceId The interface identifier to check
     * @return Boolean indicating whether the interface is supported
     */
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(IERC1155Receiver).interfaceId || interfaceId == type(IERC721Receiver).interfaceId || interfaceId == type(IERC1271).interfaceId;
    }

    /**
     * @notice Returns whether the account is currently paused
     * @return paused Boolean indicating if the account is paused
     * @return until The timestamp until which the account is paused (0 if not paused)
     */
    function isPaused() external view returns (bool paused, uint256 until) {
        return (pausedUntil > block.timestamp, pausedUntil);
    }

    /**
     * @notice Pause the account until a specified time
     * @dev Can only be called by an admin
     * @param _until The timestamp until which the account should be paused (0 for indefinite)
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function pauseAccount(uint256 _until, AdminAction memory adminAction) external onlyAdmin(AdminOperation.PAUSE_ACCOUNT, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(_until))) {
            revert InvalidOperationData();
        }

        pausedUntil = _until == 0 ? type(uint256).max : _until;
        emit AccountPaused(pausedUntil);
    }

    /**
     * @notice Unpause the account
     * @dev Can only be called by an admin
     * @param adminAction The admin action details with nonce and signature
     */
    function unpauseAccount(AdminAction memory adminAction) external onlyAdmin(AdminOperation.UNPAUSE_ACCOUNT, adminAction) {
        pausedUntil = 0;
        emit AccountUnpaused();
    }
}
