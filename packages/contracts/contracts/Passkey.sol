// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import './Secp256r1.sol';
import './Base64.sol';

contract Passkey {
    error InvalidSignature(string publicKey, string signature);
    error InvalidFormat();

    address public owner;
    mapping(bytes32 => mapping(bytes32 => bool)) private usedSignatures;

    event SignatureVerified(bytes32 publicKeyHash, bytes32 signatureHash, bool isValid);

    modifier onlyOwner() {
        require(msg.sender == owner, 'Only the owner can access this function.');
        _;
    }
    modifier signatureNotUsed(string memory publicKey, string memory signature) {
        if (usedSignatures[_hashString(publicKey)][_hashString(signature)]) {
            revert InvalidSignature(publicKey, signature);
        }
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function _bytesToUint256(bytes memory b) private pure returns (uint256) {
        uint256 number = abi.decode(b, (uint256));
        return number;
    }

    function _validateDERFieldLength(bytes memory field) private pure {
        uint8 numberOfMetadataBytes = 2; // sequence1 Tag and Length
        // field[0] is the Tag
        // field[1] is the Length
        if (field.length < numberOfMetadataBytes || field.length != uint8(field[1]) + numberOfMetadataBytes) {
            revert InvalidFormat();
        }
    }

    function _parseDERPublicKey(string memory publicKey) private pure returns (bytes memory, bytes memory, bytes memory) {
        bytes memory publicKeyBytes = Base64.decode(publicKey);
        _validateDERFieldLength(publicKeyBytes);
        // sequence1 Tag
        uint8 count = 0;
        count++;
        // sequence1 Length
        count++;
        // sequence2 Tag
        count++;
        // sequence2 Length
        count++;
        // objectIdentifier1 Tag
        count++;
        // objectIdentifier1 Length
        uint8 objectIdentifier1Len = uint8(publicKeyBytes[count]);
        count++;
        bytes memory objectIdentifier1 = new bytes(objectIdentifier1Len);
        for (uint8 i = 0; i < objectIdentifier1Len; i++) {
            objectIdentifier1[i] = publicKeyBytes[count];
            count++;
        }
        // objectIdentifier2 Tag
        count++;
        // objectIdentifier2 Length
        uint8 objectIdentifier2Len = uint8(publicKeyBytes[count]);
        count++;
        bytes memory objectIdentifier2 = new bytes(objectIdentifier2Len);
        for (uint8 i = 0; i < objectIdentifier2Len; i++) {
            objectIdentifier2[i] = publicKeyBytes[count];
            count++;
        }
        // bitString Tag
        count++;
        // bitString Length
        uint8 bitStringLen = uint8(publicKeyBytes[count]);
        count++;
        // number of padding bits (0)
        count++;
        // bitString length also includes the number of padding bits
        uint8 publicKeyLen = bitStringLen - 1;
        bytes memory parsedPublicKeyBytes = new bytes(publicKeyLen);
        for (uint8 i = 0; i < publicKeyLen; i++) {
            parsedPublicKeyBytes[i] = publicKeyBytes[count];
            count++;
        }

        return (objectIdentifier1, objectIdentifier2, parsedPublicKeyBytes);
    }

    function _DERInteger(bytes memory integer, uint256 expectedLength) private pure returns (bytes memory) {
        if (integer.length == expectedLength) {
            return integer;
        }

        bytes memory newInteger = new bytes(expectedLength);

        if (integer.length < expectedLength) {
            uint256 numberOfMissingBytes = expectedLength - integer.length;
            for (uint8 i = 0; i < numberOfMissingBytes; i++) {
                newInteger[i] = 0x00;
            }
            for (uint8 i = 0; i < integer.length; i++) {
                newInteger[i + numberOfMissingBytes] = integer[i];
            }
            return newInteger;
        }

        uint256 numberOfExtraBytes = integer.length - expectedLength;
        for (uint8 i = 0; i < expectedLength; i++) {
            newInteger[i] = integer[i + numberOfExtraBytes];
        }

        return newInteger;
    }

    function _parseDERSignature(string memory signature) private pure returns (bytes memory, bytes memory) {
        bytes memory signatureBytes = Base64.decode(signature);
        _validateDERFieldLength(signatureBytes);
        // sequence1 Tag
        uint8 count = 0;
        count++;
        // sequence1 Length
        count++;
        // integer1 Tag
        count++;
        // integer1 Length
        uint8 integer1Len = uint8(signatureBytes[count]);
        count++;

        bytes memory integer1 = new bytes(integer1Len);
        for (uint8 i = 0; i < integer1Len; i++) {
            integer1[i] = signatureBytes[count];
            count++;
        }
        // integer2 Tag
        count++;
        // integer2 Length
        uint8 integer2Len = uint8(signatureBytes[count]);
        count++;

        bytes memory integer2 = new bytes(integer2Len);
        for (uint8 i = 0; i < integer2Len; i++) {
            integer2[i] = signatureBytes[count];
            count++;
        }

        integer1 = _DERInteger(integer1, 32);
        integer2 = _DERInteger(integer2, 32);

        return (integer1, integer2);
    }

    function _getPublicKeyXY(string memory publicKey) private pure returns (uint256, uint256) {
        (, , bytes memory parsedPublicKey) = _parseDERPublicKey(publicKey);
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

    function _getSignatureRS(string memory signature) private pure returns (uint256, uint256) {
        (bytes memory parsedSigR, bytes memory parsedSigS) = _parseDERSignature(signature);
        uint256 sigR = _bytesToUint256(parsedSigR);
        uint256 sigS = _bytesToUint256(parsedSigS);
        return (sigR, sigS);
    }

    function _getDataHash(string memory authenticatorData, string memory clientDataJSON) private pure returns (uint256) {
        bytes memory authenticatorDataBytes = Base64.decode(authenticatorData);
        bytes memory clientDataJSONBytes = Base64.decode(clientDataJSON);
        bytes32 clientDataJSONHash = sha256(clientDataJSONBytes);
        bytes memory data = bytes.concat(authenticatorDataBytes, clientDataJSONHash);
        uint256 dataHash = uint256(sha256(data));
        return dataHash;
    }

    function _hashString(string memory str) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(str));
    }

    function verifyPassKeySignature(uint256 pubKeyX, uint256 pubKeyY, uint256 sigx, uint256 sigy, uint256 sigHash) public view returns (bool) {
        return Secp256r1.Verify(pubKeyX, pubKeyY, sigx, sigy, sigHash);
    }

    function parseAndVerifyPassKeySignature(
        string memory publicKey,
        string memory signature,
        string memory authenticatorData,
        string memory clientDataJSON
    ) public signatureNotUsed(publicKey, signature) {
        (uint256 pubKeyX, uint256 pubKeyY) = _getPublicKeyXY(publicKey);
        (uint256 sigR, uint256 sigS) = _getSignatureRS(signature);
        uint256 dataHash = _getDataHash(authenticatorData, clientDataJSON);

        bool isValid = Secp256r1.Verify(pubKeyX, pubKeyY, sigR, sigS, dataHash);

        bytes32 publicKeyHash = _hashString(publicKey);
        bytes32 signatureHash = _hashString(signature);

        if (isValid) {
            usedSignatures[publicKeyHash][signatureHash] = true;
        }

        emit SignatureVerified(publicKeyHash, signatureHash, isValid);
    }
}
