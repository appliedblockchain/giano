// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title Types
 * @author Giano Team
 * @notice A library containing common types used throughout the Giano protocol
 * @dev This library defines structs used by multiple contracts to ensure consistency
 */
library Types {
    /**
     * @notice Structure for WebAuthn signatures with public key
     * @param authenticatorData The raw authenticator data from the WebAuthn response
     * @param clientDataJSON The client data JSON from the WebAuthn response
     * @param challengeLocation Location of the challenge in the clientDataJSON
     * @param responseTypeLocation Location of the response type in the clientDataJSON
     * @param r The r component of the signature
     * @param s The s component of the signature
     * @param publicKey The public key used for the signature
     */
    struct Signature {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 challengeLocation;
        uint256 responseTypeLocation;
        uint256 r;
        uint256 s;
        PublicKey publicKey;
    }

    /**
     * @notice Structure for call parameters
     * @param target The address of the contract to call
     * @param value The amount of ETH to send with the call
     * @param data The calldata to send to the target
     */
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /**
     * @notice Structure for a signed call
     * @param call The call parameters
     * @param signature The signature authorizing the call
     */
    struct SignedCall {
        Call call;
        bytes signature;
    }
    
    /**
     * @notice Structure for an ECDSA P-256 public key
     * @param x The x coordinate of the public key (32 bytes)
     * @param y The y coordinate of the public key (32 bytes)
     */
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }
}
