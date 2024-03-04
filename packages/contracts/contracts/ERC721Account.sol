// SPDX-License-Identifier: MIT

pragma solidity ^0.8.13;

import {WebAuthn} from "./WebAuthn.sol";

struct Signature {
    bytes authenticatorData;
    string clientDataJSON;
    uint256 challengeLocation;
    uint256 responseTypeLocation;
    uint256 r;
    uint256 s;
}

/**
A minimalist smart wallet implementation that allows you to transfer ERC721 tokens
 */
contract ERC721Account {
    struct PublicKey {
        bytes32 X;
        bytes32 Y;
    }

    PublicKey public publicKey;
    uint256 public currentNonce;

    function validateAndIncrementNonce(int nonce) private returns (bool) {
       return currentNonce++ == nonce; 
    }

    error InvalidNonce(uint256 expected, uint256 actual);

    modifier validNonce(uint256 nonce) {
        if (!validateAndIncrementNonce(nonce)) {
            revert InvalidNonce({
                expected: currentNonce,
                actual: nonce
            });
        }
        _;
    }

    modifier validSignature(bytes memory message, bytes calldata signature) {
        require(_validateSignature(message, signature), "Invalid signature");
        _;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    // solhint-disable-next-line no-empty-blocks
    fallback() external payable {}

    function _validateSignature(
        bytes memory message,
        bytes calldata signature
    ) private view returns (bool) {
        Signature memory sig = abi.decode(signature, (Signature));

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
                x: uint256(publicKey.X),
                y: uint256(publicKey.Y)
            });
    }

    function transferToken(
        address token,
        address to,
        uint256 tokenId,
        bytes calldata signature,
        uint256 nonce
    ) external validNonce(nonce) validSignature(
        abi.encodePacked(token, to, tokenId, nonce),
        signature
    ) {
        IERC721(token).transferFrom(address(this), to, tokenId);
    }

}
