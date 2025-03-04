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
 * @dev This contract implements WebAuthn signature verification and supports multiple keys with different permissions
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
     * @notice Error thrown when a key attempts an operation it is not authorized for
     * @param keyX The X coordinate of the unauthorized key
     * @param keyY The Y coordinate of the unauthorized key
     * @param requiredRole The minimum role required for the operation
     */
    error NotAuthorized(bytes32 keyX, bytes32 keyY, Role requiredRole);

    /**
     * @notice Error thrown when an operation is attempted on a non-existent key
     * @param keyX The X coordinate of the non-existent key
     * @param keyY The Y coordinate of the non-existent key
     */
    error KeyDoesNotExist(bytes32 keyX, bytes32 keyY);

    /**
     * @notice Error thrown when an operation is attempted on a non-existent request
     * @param requestId The ID of the non-existent request
     */
    error RequestDoesNotExist(bytes32 requestId);

    /**
     * @notice Error thrown when attempting to add a key that already exists
     * @param keyX The X coordinate of the existing key
     * @param keyY The Y coordinate of the existing key
     */
    error KeyAlreadyExists(bytes32 keyX, bytes32 keyY);

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
     * @notice Error thrown when an unauthorized address attempts to add keys
     */
    error OnlyRegistryCanAddKeys();

    /**
     * @notice Error thrown when a standard signature validation fails
     */
    error InvalidExecutorSignature();

    /**
     * @notice Error thrown when an admin signature validation fails
     */
    error InvalidAdminSignature();

    /**
     * @notice Role levels for keys associated with the account
     * @dev Higher role levels include the permissions of lower levels
     */
    enum Role {
        NONE, // Key doesn't exist or has no permissions
        EXECUTOR,
        ADMIN
    }

    /**
     * @notice Structure to store information about a key
     * @param publicKey The public key
     * @param role The role assigned to the key
     */
    struct KeyInfo {
        Types.PublicKey publicKey;
        Role role;
    }

    /**
     * @notice Structure to store information about a key request
     * @param publicKey The public key being requested
     * @param requestedRole The role being requested for the key
     * @param exists Whether the request exists
     */
    struct KeyRequest {
        Types.PublicKey publicKey;
        Role requestedRole;
        bool exists;
    }

    /**
     * @notice Types of administrative operations that can be performed
     */
    enum AdminOperation {
        APPROVE_KEY_REQUEST,
        REJECT_KEY_REQUEST,
        REMOVE_KEY,
        CHANGE_KEY_ROLE
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
     * @notice Emitted when a key addition is requested
     * @param requestId The ID of the created request
     * @param x The X coordinate of the public key
     * @param y The Y coordinate of the public key
     * @param requestedRole The requested role for the key
     */
    event KeyRequested(bytes32 indexed requestId, bytes32 x, bytes32 y, Role requestedRole);

    /**
     * @notice Emitted when a key request is approved
     * @param requestId The ID of the approved request
     * @param x The X coordinate of the public key
     * @param y The Y coordinate of the public key
     * @param role The assigned role for the key
     */
    event KeyRequestApproved(bytes32 indexed requestId, bytes32 x, bytes32 y, Role role);

    /**
     * @notice Emitted when a key request is rejected
     * @param requestId The ID of the rejected request
     */
    event KeyRequestRejected(bytes32 indexed requestId);

    /**
     * @notice Emitted when a key is added to the account
     * @param x The X coordinate of the public key
     * @param y The Y coordinate of the public key
     * @param role The assigned role for the key
     */
    event KeyAdded(bytes32 indexed x, bytes32 indexed y, Role role);

    /**
     * @notice Emitted when a key is removed from the account
     * @param x The X coordinate of the removed public key
     * @param y The Y coordinate of the removed public key
     */
    event KeyRemoved(bytes32 indexed x, bytes32 indexed y);

    /**
     * @notice Emitted when a key's role is changed
     * @param x The X coordinate of the public key
     * @param y The Y coordinate of the public key
     * @param newRole The new role assigned to the key
     */
    event KeyRoleChanged(bytes32 indexed x, bytes32 indexed y, Role newRole);

    /**
     * @notice Emitted when an administrative action is executed
     * @param operation The type of operation that was executed
     * @param nonce The nonce used for the operation
     */
    event AdminActionExecuted(AdminOperation indexed operation, uint256 nonce);

    // Mapping from key hash to key information
    mapping(bytes32 => KeyInfo) private keys;
    
    // Mapping from request ID to key request information
    mapping(bytes32 => KeyRequest) private keyRequests;
    
    // Total number of active keys
    uint256 private keyCount;
    
    // Current request nonce (incremented for each request)
    uint256 private requestNonce;
    
    // Current admin operation nonce (incremented for each admin operation)
    uint256 private adminNonce = 0;

    // Current transaction nonce (incremented for each execute call)
    uint256 private currentNonce = 0;

    // Address of the registry contract
    address public immutable registry;

    /**
     * @notice Initializes the Account with an initial admin key and registry
     * @dev Sets up the initial admin key and registers the registry
     * @param _initialAdminKey The initial public key to be given admin role
     * @param _registry The address of the AccountRegistry contract
     */
    constructor(Types.PublicKey memory _initialAdminKey, address _registry) {
        // Add the initial admin key
        bytes32 keyHash = _getKeyHash(_initialAdminKey);
        keys[keyHash] = KeyInfo({publicKey: _initialAdminKey, role: Role.ADMIN});
        keyCount = 1;
        registry = _registry;

        emit KeyAdded(_initialAdminKey.x, _initialAdminKey.y, Role.ADMIN);
    }

    /**
     * @notice Returns the expected challenge for a given call payload
     * @dev Used to verify signatures for execute calls
     * @param call The call parameters to generate the challenge against
     * @return The challenge hash for signature verification
     */
    function getChallenge(Types.Call calldata call) public view returns (bytes32) {
        return keccak256(bytes.concat(bytes20(address(this)), bytes32(currentNonce), bytes20(call.target), bytes32(call.value), call.data));
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
     * @dev Used for efficiently storing and looking up keys
     * @param _publicKey The public key to hash
     * @return The keccak256 hash of the public key
     */
    function _getKeyHash(Types.PublicKey memory _publicKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(_publicKey.x, _publicKey.y));
    }

    /**
     * @notice Checks if a key exists and has at least the specified role
     * @dev Used to verify authorization for operations
     * @param _publicKey The public key to check
     * @param _minimumRole The minimum role required
     * @return Boolean indicating whether the key has the required role
     */
    function _hasRole(Types.PublicKey memory _publicKey, Role _minimumRole) internal view returns (bool) {
        bytes32 keyHash = _getKeyHash(_publicKey);
        return uint8(keys[keyHash].role) >= uint8(_minimumRole);
    }

    /**
     * @notice Checks if a key exists (has any role)
     * @dev Used to determine whether a key has been registered
     * @param _publicKey The public key to check
     * @return Boolean indicating whether the key exists
     */
    function _keyExists(Types.PublicKey memory _publicKey) internal view returns (bool) {
        bytes32 keyHash = _getKeyHash(_publicKey);
        return keys[keyHash].role != Role.NONE;
    }

    /**
     * @notice Returns information about a specific key
     * @param _publicKey The public key to get information for
     * @return KeyInfo struct containing the key's information
     */
    function getKeyInfo(Types.PublicKey calldata _publicKey) external view returns (KeyInfo memory) {
        bytes32 keyHash = _getKeyHash(_publicKey);
        return keys[keyHash];
    }

    /**
     * @notice Gets the total number of active keys
     * @return The number of active keys associated with this account
     */
    function getKeyCount() external view returns (uint256) {
        return keyCount;
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
    modifier onlyAdmin(
        AdminOperation expectedOperation,
        AdminAction memory adminAction
    ) {
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
     * @dev Used to restrict key management functions to the registry
     */
    modifier onlyRegistry() {
        if (msg.sender != registry) {
            revert OnlyRegistryCanAddKeys();
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
     * @notice Requests to add a new key to the contract
     * @dev Can only be called by the registry
     * @param _publicKey The public key to add
     * @param _requestedRole The requested role for the key
     * @return requestId The ID of the created request
     */
    function requestAddKey(Types.PublicKey calldata _publicKey, Role _requestedRole) external onlyRegistry returns (bytes32 requestId) {
        bytes32 keyHash = _getKeyHash(_publicKey);
        if (keys[keyHash].role != Role.NONE) {
            revert KeyAlreadyExists(_publicKey.x, _publicKey.y);
        }

        requestId = keccak256(abi.encode(_publicKey.x, _publicKey.y, _requestedRole, requestNonce++));

        keyRequests[requestId] = KeyRequest({publicKey: _publicKey, requestedRole: _requestedRole, exists: true});

        emit KeyRequested(requestId, _publicKey.x, _publicKey.y, _requestedRole);

        return requestId;
    }

    /**
     * @notice Approves a key addition request
     * @dev Can only be called by an admin and notifies the registry
     * @param requestId The ID of the request to approve
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function approveKeyRequest(
        bytes32 requestId,
        AdminAction memory adminAction
    ) external onlyAdmin(AdminOperation.APPROVE_KEY_REQUEST, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(requestId))) {
            revert InvalidOperationData();
        }

        KeyRequest memory request = keyRequests[requestId];
        if (!request.exists) {
            revert RequestDoesNotExist(requestId);
        }

        bytes32 keyHash = _getKeyHash(request.publicKey);
        keys[keyHash] = KeyInfo({publicKey: request.publicKey, role: request.requestedRole});
        keyCount++;

        delete keyRequests[requestId];

        // Notify the registry about the new key
        AccountRegistry(registry).notifyKeyAdded(request.publicKey);

        emit KeyRequestApproved(requestId, request.publicKey.x, request.publicKey.y, request.requestedRole);
        emit KeyAdded(request.publicKey.x, request.publicKey.y, request.requestedRole);
    }

    /**
     * @notice Rejects a key addition request
     * @dev Can only be called by an admin
     * @param requestId The ID of the request to reject
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function rejectKeyRequest(
        bytes32 requestId,
        AdminAction memory adminAction
    ) external onlyAdmin(AdminOperation.REJECT_KEY_REQUEST, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(requestId))) {
            revert InvalidOperationData();
        }

        if (!keyRequests[requestId].exists) {
            revert RequestDoesNotExist(requestId);
        }

        delete keyRequests[requestId];

        emit KeyRequestRejected(requestId);
    }

    /**
     * @notice Removes an existing key
     * @dev Can only be called by an admin and notifies the registry
     * @param _publicKey The public key to remove
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function removeKey(
        Types.PublicKey calldata _publicKey,
        AdminAction memory adminAction
    ) external onlyAdmin(AdminOperation.REMOVE_KEY, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(_publicKey))) {
            revert InvalidOperationData();
        }

        bytes32 keyHash = _getKeyHash(_publicKey);
        if (keys[keyHash].role == Role.NONE) {
            revert KeyDoesNotExist(_publicKey.x, _publicKey.y);
        }

        keys[keyHash].role = Role.NONE;
        keyCount--;

        // Notify the registry about the removed key
        AccountRegistry(registry).notifyKeyRemoved(_publicKey);

        emit KeyRemoved(_publicKey.x, _publicKey.y);
    }

    /**
     * @notice Changes the role of an existing key
     * @dev Can only be called by an admin
     * @param _publicKey The public key to update
     * @param _newRole The new role for the key
     * @param adminAction The admin action details with operation data, nonce and signature
     */
    function changeKeyRole(
        Types.PublicKey calldata _publicKey,
        Role _newRole,
        AdminAction memory adminAction
    ) external onlyAdmin(AdminOperation.CHANGE_KEY_ROLE, adminAction) {
        if (keccak256(adminAction.operationData) != keccak256(abi.encode(_publicKey, _newRole))) {
            revert InvalidOperationData();
        }

        bytes32 keyHash = _getKeyHash(_publicKey);
        if (keys[keyHash].role == Role.NONE) {
            revert KeyDoesNotExist(_publicKey.x, _publicKey.y);
        }

        keys[keyHash].role = _newRole;

        emit KeyRoleChanged(_publicKey.x, _publicKey.y, _newRole);
    }

    /**
     * @notice Executes an arbitrary call on a smart contract
     * @dev Requires a valid signature from a key with EXECUTOR or ADMIN role
     * @param signed The parameters of the call to be executed
     */
    function execute(Types.SignedCall calldata signed) external payable validSignature(bytes.concat(getChallenge(signed.call)), signed.signature) nonReentrant {
        (bool success, bytes memory result) = signed.call.target.call{value: signed.call.value}(signed.call.data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
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

        if (!_hasRole(sig.publicKey, Role.ADMIN)) {
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
                x: uint256(sig.publicKey.x),
                y: uint256(sig.publicKey.y)
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

        Types.PublicKey memory signerKey = sig.publicKey;

        if (!_hasRole(signerKey, Role.EXECUTOR)) {
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
                x: uint256(signerKey.x),
                y: uint256(signerKey.y)
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
            interfaceId == type(IERC1155Receiver).interfaceId ||
            interfaceId == type(IERC721Receiver).interfaceId ||
            interfaceId == type(IERC1271).interfaceId;
    }
}
