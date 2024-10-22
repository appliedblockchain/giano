// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {WebAuthn} from './WebAuthn.sol';
import {IERC721} from '@openzeppelin/contracts/token/ERC721/IERC721.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';

struct Signature {
    bytes authenticatorData;
    string clientDataJSON;
    uint256 challengeLocation;
    uint256 responseTypeLocation;
    uint256 r;
    uint256 s;
}

struct Call {
    address target;
    uint256 value;
    bytes data;
    bytes signature;
}

/**
A minimalist smart wallet implementation that allows you to transfer tokens
 */
contract Account {
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

    error InvalidNonce(uint256 expected, uint256 actual);
    error InvalidSignature();

    PublicKey public publicKey;
    uint256 public currentNonce = 0;

    constructor(PublicKey memory _publicKey) {
        publicKey = _publicKey;
    }

    function getChallenge() public view returns (bytes32) {
        return keccak256(bytes.concat(bytes20(address(this)), bytes32(currentNonce)));
    }

    function getNonce() public view returns (uint256) {
        return currentNonce;
    }

    function validateAndIncrementNonce(uint256 nonce) private returns (bool) {
        return currentNonce++ == nonce;
    }

    modifier validNonce(uint256 nonce) {
        if (!validateAndIncrementNonce(nonce)) {
            revert InvalidNonce({expected: currentNonce, actual: nonce});
        }
        _;
    }

    modifier validSignature(bytes memory message, bytes calldata signature) {
        if (!_validateSignature(message, signature)) {
            revert InvalidSignature();
        }
        _;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    function execute(Call calldata call) external payable validSignature(bytes.concat(getChallenge()), call.signature) {
        (bool success, bytes memory result) = call.target.call{value: call.value}(call.data);
        if (!success) {
            // FIXME: apparently this does not work with custom errors. Investigate.
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _validateSignature(bytes memory message, bytes calldata signature) private view returns (bool) {
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
                x: uint256(publicKey.x),
                y: uint256(publicKey.y)
            });
    }
}
