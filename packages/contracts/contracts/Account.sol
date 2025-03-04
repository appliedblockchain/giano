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
A smart wallet implementation that allows you to execute arbitrary functions in contracts
with multiple signers having different roles
 */
contract Account is ReentrancyGuard, IERC1271, IERC721Receiver, IERC1155Receiver {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;

    error InvalidSignature(string reason);
    error NotAuthorized(bytes32 keyX, bytes32 keyY, Role requiredRole);
    error KeyDoesNotExist(bytes32 keyX, bytes32 keyY);
    error RequestDoesNotExist(bytes32 requestId);
    error KeyAlreadyExists(bytes32 keyX, bytes32 keyY);
    error InvalidOperation(AdminOperation expected, AdminOperation received);
    error InvalidNonce(uint256 expected, uint256 received);
    error InvalidOperationData();
    error OnlyRegistryCanAddKeys();

    enum Role {
        NONE, // Key doesn't exist or has no permissions
        EXECUTOR,
        ADMIN
    }

    struct KeyInfo {
        Types.PublicKey publicKey;
        Role role;
    }

    struct KeyRequest {
        Types.PublicKey publicKey;
        Role requestedRole;
        bool exists;
    }

    // Admin operation types
    enum AdminOperation {
        APPROVE_KEY_REQUEST,
        REJECT_KEY_REQUEST,
        REMOVE_KEY,
        CHANGE_KEY_ROLE
    }

    struct AdminAction {
        AdminOperation operation;
        bytes operationData;
        uint256 nonce;
        bytes signature;
    }

    event KeyRequested(bytes32 indexed requestId, bytes32 x, bytes32 y, Role requestedRole);
    event KeyRequestApproved(bytes32 indexed requestId, bytes32 x, bytes32 y, Role role);
    event KeyRequestRejected(bytes32 indexed requestId);
    event KeyAdded(bytes32 indexed x, bytes32 indexed y, Role role);
    event KeyRemoved(bytes32 indexed x, bytes32 indexed y);
    event KeyRoleChanged(bytes32 indexed x, bytes32 indexed y, Role newRole);
    event AdminActionExecuted(AdminOperation indexed operation, uint256 nonce);

    mapping(bytes32 => KeyInfo) private keys;
    mapping(bytes32 => KeyRequest) private keyRequests;
    uint256 private keyCount;
    uint256 private requestNonce;
    uint256 private adminNonce = 0;

    uint256 private currentNonce = 0;

    address public immutable registry;

    constructor(Types.PublicKey memory _initialAdminKey, address _registry) {
        // Add the initial admin key
        bytes32 keyHash = _getKeyHash(_initialAdminKey);
        keys[keyHash] = KeyInfo({publicKey: _initialAdminKey, role: Role.ADMIN});
        keyCount = 1;
        registry = _registry;

        emit KeyAdded(_initialAdminKey.x, _initialAdminKey.y, Role.ADMIN);
    }

    /**
     * Returns the expected challenge for a given call payload
     * @param call The call parameters to generate the challenge against
     */
    function getChallenge(Types.Call calldata call) public view returns (bytes32) {
        return keccak256(bytes.concat(bytes20(address(this)), bytes32(currentNonce), bytes20(call.target), bytes32(call.value), call.data));
    }

    /**
     * Returns the expected challenge for an admin operation
     * @param adminAction The admin action to generate the challenge against
     */
    function getAdminChallenge(AdminAction memory adminAction) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), adminAction.operation, adminAction.operationData, adminAction.nonce));
    }

    /**
     * Get the hash of a public key
     */
    function _getKeyHash(Types.PublicKey memory _publicKey) internal pure returns (bytes32) {
        return keccak256(abi.encode(_publicKey.x, _publicKey.y));
    }

    /**
     * Check if a key exists and has at least the specified role
     */
    function _hasRole(Types.PublicKey memory _publicKey, Role _minimumRole) internal view returns (bool) {
        bytes32 keyHash = _getKeyHash(_publicKey);
        return uint8(keys[keyHash].role) >= uint8(_minimumRole);
    }

    /**
     * Check if a key exists (has any role)
     */
    function _keyExists(Types.PublicKey memory _publicKey) internal view returns (bool) {
        bytes32 keyHash = _getKeyHash(_publicKey);
        return keys[keyHash].role != Role.NONE;
    }

    /**
     * Returns information about a specific key
     */
    function getKeyInfo(Types.PublicKey calldata _publicKey) external view returns (KeyInfo memory) {
        bytes32 keyHash = _getKeyHash(_publicKey);
        return keys[keyHash];
    }

    /**
     * Get the total number of keys
     */
    function getKeyCount() external view returns (uint256) {
        return keyCount;
    }

    /**
     * Get the current admin nonce
     */
    function getAdminNonce() external view returns (uint256) {
        return adminNonce;
    }

    modifier validSignature(bytes memory message, bytes calldata signature) {
        if (!_validateSignature(message, signature)) {
            revert InvalidSignature('Signature verification failed');
        }
        _;
    }

    modifier onlyAdmin(
        AdminOperation expectedOperation,
        AdminAction memory adminAction
    ) {
        if (adminAction.operation != expectedOperation) {
            revert InvalidOperation(expectedOperation, adminAction.operation);
        }

        bytes32 challenge = getAdminChallenge(adminAction);

        if (!_validateAdminSignature(bytes.concat(challenge), adminAction.signature)) {
            revert InvalidSignature('Admin signature verification failed');
        }

        if (adminAction.nonce != adminNonce) {
            revert InvalidNonce(adminNonce, adminAction.nonce);
        }

        adminNonce++;

        emit AdminActionExecuted(adminAction.operation, adminAction.nonce);
        _;
    }

    modifier onlyRegistry() {
        if (msg.sender != registry) {
            revert OnlyRegistryCanAddKeys();
        }
        _;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    // solhint-disable-next-line no-empty-blocks
    fallback() external payable {}

    /**
     * Request to add a new key to the contract
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
     * Approve a key addition request (admin only)
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
     * Reject a key addition request (admin only)
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
     * Remove an existing key (admin only)
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
     * Change the role of an existing key (admin only)
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
     * Execute an arbitrary call on a smart contract, optionally sending a value in ETH
     * @param signed The parameters of the call to be executed
     * @notice The call parameters must be signed with a key that has EXECUTOR or ADMIN role
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
     * Validates a signature for an admin operation
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
     * @inheritdoc IERC1271
     */
    function isValidSignature(bytes32 messageHash, bytes calldata signature) public view override returns (bytes4 magicValue) {
        if (_validateSignature(bytes.concat(messageHash), signature)) {
            return ERC1271_MAGICVALUE;
        }
        return 0xffffffff;
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(IERC1155Receiver).interfaceId ||
            interfaceId == type(IERC721Receiver).interfaceId ||
            interfaceId == type(IERC1271).interfaceId;
    }
}
