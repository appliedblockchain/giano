// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import '../Base64.sol';
import './Asn1Parser.sol';

library PassKeyParser {
    function _bytesToUint256(bytes memory b) private pure returns (uint256) {
        uint256 number = abi.decode(b, (uint256));
        return number;
    }

    function getPublicKeyXY(string memory publicKey) internal pure returns (uint256, uint256) {
        (, , bytes memory parsedPublicKey) = Asn1Parser.parsePublicKey(publicKey);
        uint8 parsedPublicKeyLen = uint8(parsedPublicKey.length) - 1;

        uint8 count = 0;
        // Remove the first byte (0x04)
        count++;

        bytes memory pubKeyXBytes = new bytes(parsedPublicKeyLen / 2);
        for (uint8 i = 0; i < parsedPublicKeyLen / 2; i++) {
            pubKeyXBytes[i] = parsedPublicKey[count];
            count++;
        }

        bytes memory pubKeyYBytes = new bytes(parsedPublicKeyLen / 2);
        for (uint8 i = 0; i < parsedPublicKeyLen / 2; i++) {
            pubKeyYBytes[i] = parsedPublicKey[count];
            count++;
        }

        uint256 pubKeyX = _bytesToUint256(pubKeyXBytes);
        uint256 pubKeyY = _bytesToUint256(pubKeyYBytes);

        return (pubKeyX, pubKeyY);
    }

    function getSignatureRS(string memory signature) internal pure returns (uint256, uint256) {
        (bytes memory parsedSigR, bytes memory parsedSigS) = Asn1Parser.parseSignature(signature);
        uint256 sigR = _bytesToUint256(parsedSigR);
        uint256 sigS = _bytesToUint256(parsedSigS);
        return (sigR, sigS);
    }

    function getDataHash(string memory authenticatorData, string memory clientDataJSON) internal pure returns (uint256) {
        bytes memory authenticatorDataBytes = Base64.decode(authenticatorData);
        bytes memory clientDataJSONBytes = Base64.decode(clientDataJSON);
        bytes32 clientDataJSONHash = sha256(clientDataJSONBytes);
        bytes memory data = bytes.concat(authenticatorDataBytes, clientDataJSONHash);
        uint256 dataHash = uint256(sha256(data));
        return dataHash;
    }
}
