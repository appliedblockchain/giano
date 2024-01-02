// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import './Base64.sol';
import './Secp256r1.sol';

contract PassKey {
    address public owner;
    //
    mapping(bytes32 => PassKeyId) private authorisedKeys;
    bytes32[] private knownKeyHashes;

    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, 'Only the owner can access this function.');
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addPassKey(string calldata _keyId, uint256 _pubKeyX, uint256 _pubKeyY) external onlyOwner {
        _addPassKey(keccak256(abi.encodePacked(_keyId)), _pubKeyX, _pubKeyY, _keyId);
    }

    function _addPassKey(bytes32 _keyHash, uint256 _pubKeyX, uint256 _pubKeyY, string calldata _keyId) internal {
        authorisedKeys[_keyHash] = PassKeyId(_pubKeyX, _pubKeyY, _keyId);
        knownKeyHashes.push(_keyHash);
    }

    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
        //lighter signature scheme. must match UserOp.ts#packUserOp
        bytes calldata sig = userOp.signature;
        // copy directly the userOp from calldata up to (but not including) the signature.
        // this encoding depends on the ABI encoding of calldata, but is much lighter to copy
        // than referencing each field separately.
        assembly {
            let ofs := userOp
            let len := sub(sub(sig.offset, ofs), 32)
            ret := mload(0x40)
            mstore(0x40, add(ret, add(len, 32)))
            mstore(ret, len)
            calldatacopy(add(ret, 32), ofs, len)
        }
    }

    function hash(UserOperation calldata userOp) public pure returns (bytes32) {
        return keccak256(pack(userOp));
    }

    // ref: https://github.com/itsobvioustech/aa-passkeys-wallet/blob/main/src/PassKeysAccount.sol#L84
    function validateSignature(UserOperation calldata userOp, bytes32 userOpHash) public view returns (uint256 validationData) {
        (bytes32 keyHash, uint256 sigx, uint256 sigy, bytes memory authenticatorData, string memory clientDataJSONPre, string memory clientDataJSONPost) = abi
            .decode(userOp.signature, (bytes32, uint256, uint256, bytes, string, string));

        string memory opHashBase64 = Base64.encode(bytes.concat(userOpHash));
        string memory clientDataJSON = string.concat(clientDataJSONPre, opHashBase64, clientDataJSONPost);
        bytes32 clientHash = sha256(bytes(clientDataJSON));
        bytes32 sigHash = sha256(bytes.concat(authenticatorData, clientHash));

        PassKeyId memory passKey = authorisedKeys[keyHash];
        require(Secp256r1.Verify(passKey, sigx, sigy, uint256(sigHash)), 'Invalid signature');
        return 0;
    }

    function verifyPassKeySignature(PassKeyId calldata passKey, uint256 sigx, uint256 sigy, uint256 sigHash) public view returns (bool) {
        return Secp256r1.Verify(passKey, sigx, sigy, sigHash);
    }
}
