// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {P256} from "./P256.sol";
import {Base64} from "./Base64.sol";

/**
 * @title WebAuthn
 * @author Giano Team
 * @notice Helper library for verifying WebAuthn signatures in Solidity
 * @dev Implements verification of WebAuthn authentication assertions following
 * the W3C WebAuthn specification (https://w3c.github.io/webauthn/)
 */
library WebAuthn {
    /**
     * @notice Checks whether a substring occurs in a string at a given byte offset
     * @dev Used to verify challenge and response type in the clientDataJSON
     * @param substr The substring to search for
     * @param str The string to search in
     * @param location The starting byte offset in the string
     * @return True if the substring was found at the specified location
     */
    function contains(
        string memory substr,
        string memory str,
        uint256 location
    ) internal pure returns (bool) {
        bytes memory substrBytes = bytes(substr);
        bytes memory strBytes = bytes(str);

        uint256 substrLen = substrBytes.length;
        uint256 strLen = strBytes.length;

        for (uint256 i = 0; i < substrLen; i++) {
            if (location + i >= strLen) {
                return false;
            }

            if (substrBytes[i] != strBytes[location + i]) {
                return false;
            }
        }

        return true;
    }

    // Constants for authenticator data flags
    bytes1 constant AUTH_DATA_FLAGS_UP = 0x01; // User Present (Bit 0)
    bytes1 constant AUTH_DATA_FLAGS_UV = 0x04; // User Verified (Bit 2)
    bytes1 constant AUTH_DATA_FLAGS_BE = 0x08; // Backup Eligibility (Bit 3)
    bytes1 constant AUTH_DATA_FLAGS_BS = 0x10; // Backup State (Bit 4)

    /**
     * @notice Verifies the authentication flags in authenticatorData
     * @dev Validates flags according to the WebAuthn spec section on verifying assertion
     * @param flags The flags byte from the authenticatorData
     * @param requireUserVerification Whether user verification is required
     * @return True if the flags are valid according to the spec
     */
    function checkAuthFlags(
        bytes1 flags,
        bool requireUserVerification
    ) internal pure returns (bool) {
        // 17. Verify that the UP bit of the flags in authData is set.
        if (flags & AUTH_DATA_FLAGS_UP != AUTH_DATA_FLAGS_UP) {
            return false;
        }

        // 18. If user verification was determined to be required, verify that
        // the UV bit of the flags in authData is set. Otherwise, ignore the
        // value of the UV flag.
        if (
            requireUserVerification &&
            (flags & AUTH_DATA_FLAGS_UV) != AUTH_DATA_FLAGS_UV
        ) {
            return false;
        }

        // 19. If the BE bit of the flags in authData is not set, verify that
        // the BS bit is not set.
        if (flags & AUTH_DATA_FLAGS_BE != AUTH_DATA_FLAGS_BE) {
            if (flags & AUTH_DATA_FLAGS_BS == AUTH_DATA_FLAGS_BS) {
                return false;
            }
        }

        return true;
    }

    /**
     * @notice Verifies a WebAuthn P256 signature (Authentication Assertion)
     * @dev Implements partial verification of WebAuthn assertions as described in
     * https://w3c.github.io/webauthn/#sctn-verifying-assertion
     * 
     * This function verifies:
     * - That authenticatorData indicates a well-formed assertion with appropriate flags
     * - That the client JSON is of type "webauthn.get"
     * - That the client JSON contains the requested challenge
     * - That the signature is valid for the provided P256 public key
     * 
     * Note that this implementation makes certain assumptions suitable for the Giano
     * protocol and does NOT verify all aspects of the WebAuthn specification.
     * 
     * @param challenge The challenge that was sent to the authenticator
     * @param authenticatorData The raw authenticator data from the WebAuthn response
     * @param requireUserVerification Whether user verification is required
     * @param clientDataJSON The client data JSON from the WebAuthn response
     * @param challengeLocation Location of the challenge in the clientDataJSON
     * @param responseTypeLocation Location of the response type in the clientDataJSON
     * @param r The r component of the signature
     * @param s The s component of the signature
     * @param x The x coordinate of the public key
     * @param y The y coordinate of the public key
     * @return True if the signature is valid
     */
    function verifySignature(
        bytes memory challenge,
        bytes memory authenticatorData,
        bool requireUserVerification,
        string memory clientDataJSON,
        uint256 challengeLocation,
        uint256 responseTypeLocation,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        // Check that authenticatorData has good flags
        if (
            authenticatorData.length < 32 ||
            !checkAuthFlags(authenticatorData[32], requireUserVerification)
        ) {
            return false;
        }

        // Check that response is for an authentication assertion
        string memory responseType = '"type":"webauthn.get"';
        if (!contains(responseType, clientDataJSON, responseTypeLocation)) {
            return false;
        }

        // Check that challenge is in the clientDataJSON
        string memory challengeB64url = Base64.encodeURL(challenge);
        string memory challengeProperty = string.concat(
            '"challenge":"',
            challengeB64url,
            '"'
        );

        if (!contains(challengeProperty, clientDataJSON, challengeLocation)) {
            return false;
        }

        // Check that the public key signed sha256(authenticatorData || sha256(clientDataJSON))
        bytes32 clientDataJSONHash = sha256(bytes(clientDataJSON));
        bytes32 messageHash = sha256(
            abi.encodePacked(authenticatorData, clientDataJSONHash)
        );

        // check that the signature is valid while allowing malleability
        return P256.verifySignatureAllowMalleability(messageHash, r, s, x, y);
    }
}
