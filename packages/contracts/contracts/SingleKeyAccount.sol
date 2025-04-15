// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {WebAuthn} from './WebAuthn.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {Types} from './Types.sol';
import {TokenReceiver} from './TokenReceiver.sol';

/**
A smart wallet implementation that allows you to execute arbitrary functions in contracts
 */
contract SingleKeyAccount is ReentrancyGuard, TokenReceiver, IERC1271 {
    error InvalidSignature();
    error ExpiredStaticSignature(uint256 expiredAt, uint256 currentTimestamp);

    // todo: worth it to make it configurable?
    uint256 constant private STATIC_CHALLENGE_VALIDITY_SECONDS = 60;

    Types.PublicKey private publicKey;
    uint256 private currentNonce = 0;

    struct StaticCall {
        address target;
        bytes data;
        uint256 expiresAt;
    }

    struct SignedStaticCall {
        StaticCall call;
        bytes signature;
    }

    constructor(Types.PublicKey memory _publicKey) {
        publicKey = _publicKey;
    }

    /**
     * Returns the expected challenge for a given call payload
     * @param call The call parameters to generate the challenge against
     */
    function getChallenge(Types.Call calldata call) public view returns (bytes32) {
        return keccak256(bytes.concat(bytes20(address(this)), bytes32(currentNonce), bytes20(call.target), bytes32(call.value), call.data));
    }

    /**
     * Returns a valid challenge for static calls, good for STATIC_CHALLENGE_VALIDITY_SECONDS seconds
     * @param call The call parameters to generate the challenge against
     * @return payload The payload to be signed
     */
    function getStaticChallenge(StaticCall calldata call) public view returns (bytes32 payload) {
        payload = keccak256(bytes.concat(bytes20(address(this)), bytes32(call.expiresAt), bytes20(call.target), call.data));
    }

    /**
     * Returns the x and y coordinates of the public key associated with this contract
     */
    function getPublicKey() public view returns (Types.PublicKey memory) {
        return publicKey;
    }

    modifier validSignature(bytes memory message, bytes calldata signature) {
        require(_validateSignature(message, signature), InvalidSignature());
        _;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}

    // solhint-disable-next-line no-empty-blocks
    fallback() external payable {}

    /**
     * Execute an arbitrary call on a smart contract, optionally sending a value in ETH
     * @param signed The parameters of the call to be executed
     * @notice The call parameters must be signed with the key associated with this contract
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
     * Execute an arbitrary static (view) call on a smart contract, optionally sending a value in ETH
     * @param signed The parameters of the call to be executed
     * @notice The call parameters must be signed with the key associated with this contract
     */
    function staticCall(
        SignedStaticCall calldata signed
    ) external view validSignature(bytes.concat(getStaticChallenge(signed.call)), signed.signature) returns (bytes memory) {
        require(block.timestamp < signed.call.expiresAt, ExpiredStaticSignature(signed.call.expiresAt, block.timestamp));
        (bool success, bytes memory result) = signed.call.target.staticcall(signed.call.data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        return result;
    }

    function _validateSignature(bytes memory message, bytes calldata signature) private view returns (bool) {
        Types.SingleKeyAccountSignature memory sig = abi.decode(signature, (Types.SingleKeyAccountSignature));

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
                x: publicKey.x,
                y: publicKey.y
            });
    }

    /**
     * @inheritdoc IERC1271
     */
    function isValidSignature(bytes32 messageHash, bytes calldata signature) public view override returns (bytes4 magicValue) {
        return _validateSignature(bytes.concat(messageHash), signature) ? this.isValidSignature.selector : bytes4(0xffffffff);
    }

    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return super.supportsInterface(interfaceId) || interfaceId == type(IERC1271).interfaceId;
    }
}
