// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Base64Url} from "FreshCryptoLib/utils/Base64Url.sol";
import "webauthn-sol/../test/Utils.sol";

import {MockEntryPoint} from "../mocks/MockEntryPoint.sol";
import "./SmartWalletTestBase.sol";

/// A passkey signature counts only when the authenticator verified the user (UV), not merely that
/// someone was present (UP). See docs/G4-WEBAUTHN-USER-VERIFICATION.md.
contract TestUserVerification is SmartWalletTestBase {
    bytes1 constant UP = 0x01;
    bytes1 constant UV = 0x04;
    bytes1 constant UP_UV = 0x05;

    bytes32 constant HASH = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;

    /// A genuine passkey signature over `challenge` whose authenticatorData carries `flags`.
    function _passkeySignature(bytes32 challenge, bytes1 flags) internal view returns (bytes memory) {
        string memory clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64Url.encode(abi.encode(challenge)),
            '","origin":"https://wallet.example","crossOrigin":false}'
        );
        bytes memory authenticatorData =
            abi.encodePacked(hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763", flags, hex"00000000");
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, messageHash);
        return abi.encode(
            GianoSmartWallet.SignatureWrapper({
                ownerBytes: passkeyOwner,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: authenticatorData,
                        clientDataJSON: clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: Utils.normalizeS(uint256(s))
                    })
                )
            })
        );
    }

    function _isValid(bytes1 flags) internal view returns (bool) {
        bytes memory sig = _passkeySignature(account.replaySafeHash(HASH), flags);
        return account.isValidSignature(HASH, sig) == bytes4(0x1626ba7e);
    }

    function test_isValidSignature_acceptsUserVerified() public view {
        assertTrue(_isValid(UP_UV));
    }

    function test_isValidSignature_rejectsPresenceOnly() public view {
        assertFalse(_isValid(UP));
    }

    function test_isValidSignature_rejectsNoFlags() public view {
        assertFalse(_isValid(0x00));
    }

    /// webauthn-sol still requires UP; UV alone is not enough.
    function test_isValidSignature_rejectsVerifiedWithoutPresence() public view {
        assertFalse(_isValid(UV));
    }

    function test_validateUserOp_rejectsPresenceOnly() public {
        bytes32 userOpHash = keccak256("123");
        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        PackedUserOperation memory userOp;
        userOp.signature = _passkeySignature(userOpHash, UP_UV);
        assertEq(ep.validateUserOp(address(account), userOp, userOpHash, 0), 0);

        userOp.signature = _passkeySignature(userOpHash, UP);
        assertEq(ep.validateUserOp(address(account), userOp, userOpHash, 0), 1);
    }
}
