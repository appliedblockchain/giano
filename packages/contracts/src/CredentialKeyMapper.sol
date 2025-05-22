// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title CredentialKeyMapper
 * @notice Maps a WebAuthn credential ID to its corresponding elliptic-curve
 *         public key. Each credential can be registered **once** and later
 *         looked up or removed by proving possession of that key.
 * @author Applied Blockchain
 * @dev The contract relies on the `WebAuthn.verify` helper to authenticate the
 *      caller via an ECDSA-P256 signature produced by the WebAuthn authenticator
 *      that owns the credential. All state-changing methods compute an EIP-191
 *      style hash of the exact calldata being authorised and feed it to
 *      `WebAuthn.verify`.  This protects against both signature malleability
 *      and replay across different contract methods.
 */
import {WebAuthn} from 'webauthn-sol/WebAuthn.sol';

contract CredentialKeyMapper {
    /**
     * @dev Affine coordinates of a P-256 public key.
     */
    struct PublicKey {
        /// @custom:field x X-coordinate of the point on secp256r1.
        bytes32 x;
        /// @custom:field y Y-coordinate of the point on secp256r1.
        bytes32 y;
    }

    /**
     * @dev Reverts when attempting to register a credential ID that is already
     *      present in `_keys`.
     * @param idHash The hash of the credential ID that has already been set.
     */
    error CredentialIdAlreadySet(bytes32 idHash);

    error InvalidKey(bytes32 x, bytes32 y);
    error EmptyCredentialId();

    /// @dev Maps the hash of a credential ID (`id`) to its corresponding public key.
    mapping(bytes32 => PublicKey) private _keys;

    /**
     * @notice Internal helper that reverts unless `signature` is a valid
     *         WebAuthn assertion over `hash` produced by the holder of the
     *         `(x, y)` public key.
     *
     * @param hash      The EIP-191 compliant hash that must have been signed.
     * @param signature The raw CBOR-encoded WebAuthn assertion data returned by
     *                  the client (see `WebAuthn.WebAuthnAuth`).
     * @param x         X-coordinate of the expected public key.
     * @param y         Y-coordinate of the expected public key.
     *
     * @dev The function is `view` because `WebAuthn.verify` does not modify
     *      state; it will revert if verification fails.
     */
    function _validSignature(bytes32 hash, bytes calldata signature, bytes32 x, bytes32 y) private view {
        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth));
        WebAuthn.verify({challenge: abi.encode(hash), requireUV: false, webAuthnAuth: auth, x: uint256(x), y: uint256(y)});
    }

    /**
     * @notice Register a new credential → public-key mapping.
     *
     * @param idHash        The keccak256 hash of the credential ID returned by the authenticator during
     *                  WebAuthn registration.
     * @param key       The public key (affine coordinates) that corresponds to
     *                  `id`.
     * @custom:reverts CredentialIdAlreadySet When `id` is already in `_keys`.
     * @custom:reverts InvalidKey          When no key is stored under `id`.
     * @custom:reverts (from _validSignature)  When the signature fails to
     *                                         validate.
     */
    function setCredentialKey(bytes32 idHash, PublicKey calldata key) external {
        if (_keys[idHash].x != bytes32(0)) {
            revert CredentialIdAlreadySet(idHash);
        }

        if (idHash.length == 0) {
            revert EmptyCredentialId();
        }

        if (key.x == bytes32(0) || key.y == bytes32(0)) {
            revert InvalidKey(key.x, key.y);
        }

        _keys[idHash] = key;
    }

    /**
     * @notice Retrieve the public key associated with a credential ID.
     * @param idHash The credential identifier whose public key is requested.
     * @return key The stored `PublicKey` struct (`x`, `y`). If the credential is
     *             unknown, both coordinates will be zero.
     */
    function getCredentialKey(bytes32 idHash) external view returns (PublicKey memory key) {
        key = _keys[idHash];
    }

    /**
     * @notice Remove an existing credential → public-key mapping.
     *
     * @param idHash        The hash of the credential ID to forget.
     * @param signature A valid WebAuthn assertion proving control of the key
     *                  currently registered under `id`.
     *
     * @dev The hash that must be signed is
     *      `keccak256(this.removeCredentialKey.selector || id)`.
     */
    function removeCredentialKey(bytes32 idHash, bytes calldata signature) external {
        bytes32 hash = keccak256(bytes.concat(this.removeCredentialKey.selector, idHash));
        _validSignature(hash, signature, _keys[idHash].x, _keys[idHash].y);
        delete _keys[idHash];
    }
}
