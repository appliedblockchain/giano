// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {WebAuthn} from './WebAuthn.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';

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
}
struct SignedCall {
    Call call;
    bytes signature;
}

/**
A smart wallet implementation that allows you to execute arbitrary functions in contracts
 */
contract Account is ReentrancyGuard {
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

    error InvalidSignature();

    PublicKey private publicKey;
    uint256 private currentNonce = 0;

    constructor(PublicKey memory _publicKey) {
        publicKey = _publicKey;
    }

    function getChallenge(Call calldata call) public view returns (bytes32) {
        return keccak256(bytes.concat(bytes20(address(this)), bytes32(currentNonce), bytes20(call.target), bytes32(call.value), call.data));
    }

    function getPublicKey() public view returns (PublicKey memory) {
        return publicKey;
    }

    modifier validSignature(bytes memory message, bytes calldata signature) {
        if (!_validateSignature(message, signature)) {
            revert InvalidSignature();
        }
        _;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    // solhint-disable-next-line no-empty-blocks
    fallback() external payable {}

    function execute(SignedCall calldata signed) external payable validSignature(bytes.concat(getChallenge(signed.call)), signed.signature) nonReentrant {
        (bool success, bytes memory result) = signed.call.target.call{value: signed.call.value}(signed.call.data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        currentNonce++;
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
