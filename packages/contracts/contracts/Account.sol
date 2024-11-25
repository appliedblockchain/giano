// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {WebAuthn} from './WebAuthn.sol';
import {ReentrancyGuard} from '@openzeppelin/contracts/utils/ReentrancyGuard.sol';
import {IERC1271} from '@openzeppelin/contracts/interfaces/IERC1271.sol';
import {Types} from './Types.sol';

/**
A smart wallet implementation that allows you to execute arbitrary functions in contracts
 */
contract Account is ReentrancyGuard, IERC1271 {
    // bytes4(keccak256("isValidSignature(bytes32,bytes)")
    bytes4 internal constant ERC1271_MAGICVALUE = 0x1626ba7e;

    error InvalidSignature();

    Types.PublicKey private publicKey;
    uint256 private currentNonce = 0;

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
     * Returns the x and y coordinates of the public key associated with this contract
     */
    function getPublicKey() public view returns (Types.PublicKey memory) {
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

    function _validateSignature(bytes memory message, bytes calldata signature) private view returns (bool) {
        Types.Signature memory sig = abi.decode(signature, (Types.Signature));

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

    /**
     * @inheritdoc IERC1271
     */
    function isValidSignature(bytes32 messageHash, bytes calldata signature) public view override returns (bytes4 magicValue) {
        if (_validateSignature(bytes.concat(messageHash), signature)) {
            return ERC1271_MAGICVALUE;
        }
        return 0xffffffff;
    }
}
