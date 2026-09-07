// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./SmartWalletTestBase.sol";
import "webauthn-sol/../test/Utils.sol";

contract TestIsValidSignature is SmartWalletTestBase {
    function testValidateSignatureWithPasskeySigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        bytes memory sig = abi.encode(
            GianoSmartWallet.SignatureWrapper({
                ownerBytes: passkeyOwner,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: uint256(s)
                    })
                )
            })
        );

        // check a valid signature
        bytes4 ret = account.isValidSignature(hash, sig);
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testSmartWalletSigner() public {
        MockGianoSmartWallet otherAccount = new MockGianoSmartWallet();
        otherAccount.initialize(owners);

        vm.prank(signer);
        account.addOwnerAddress(address(otherAccount));

        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = account.replaySafeHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, otherAccount.replaySafeHash(toSign));
        bytes memory signature = abi.encodePacked(r, s, v);

        GianoSmartWallet.SignatureWrapper memory wrapperForOtherAccount =
            GianoSmartWallet.SignatureWrapper(abi.encode(signer), signature);

        bytes memory sig = abi.encode(
            GianoSmartWallet.SignatureWrapper({
                ownerBytes: abi.encode(address(otherAccount)),
                signatureData: abi.encode(wrapperForOtherAccount)
            })
        );

        // check a valid signature
        bytes4 ret = account.isValidSignature(hash, sig);
        assertEq(ret, bytes4(0x1626ba7e));
    }

    /// @dev Owners are identified by their bytes rather than by index, so an unregistered
    ///      public key is rejected up front by `isOwnerBytes` instead of reverting on a lookup.
    function testValidateSignatureWithPasskeySignerFailsUnregisteredOwner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        // a well-formed passkey signature, but under a public key that was never added as an owner
        bytes memory unregisteredOwner = abi.encode(uint256(1), uint256(2));
        assertFalse(account.isOwnerBytes(unregisteredOwner));

        bytes memory sig = abi.encode(
            GianoSmartWallet.SignatureWrapper({
                ownerBytes: unregisteredOwner,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: uint256(s)
                    })
                )
            })
        );

        bytes4 ret = account.isValidSignature(hash, sig);
        assertEq(ret, bytes4(0xffffffff));
    }

    function testValidateSignatureWithPasskeySignerFailsWithWrongBadSignature() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        bytes memory sig = abi.encode(
            GianoSmartWallet.SignatureWrapper({
                ownerBytes: passkeyOwner,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r) - 1,
                        s: uint256(s)
                    })
                )
            })
        );

        // check a valid signature
        bytes4 ret = account.isValidSignature(hash, sig);
        assertEq(ret, bytes4(0xffffffff));
    }

    function testValidateSignatureWithEOASigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = account.replaySafeHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes4 ret =
            account.isValidSignature(hash, abi.encode(GianoSmartWallet.SignatureWrapper(abi.encode(signer), signature)));
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function testValidateSignatureWithEOASignerFailsWithWrongSigner() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xa12ce, hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        bytes4 ret =
            account.isValidSignature(hash, abi.encode(GianoSmartWallet.SignatureWrapper(abi.encode(signer), signature)));
        assertEq(ret, bytes4(0xffffffff));
    }

    function testReturnsInvalidIfPasskeySigButWrongOwnerLength() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 challenge = account.replaySafeHash(hash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(challenge);

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        bytes memory sig = abi.encode(
            GianoSmartWallet.SignatureWrapper({
                ownerBytes: abi.encode(signer),
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r) - 1,
                        s: uint256(s)
                    })
                )
            })
        );

        bytes4 ret = account.isValidSignature(hash, sig);
        assertEq(ret, bytes4(0xffffffff));
    }

    function testRevertsIfEthereumSignatureButWrongOwnerLength() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = SignatureCheckerLib.toEthSignedMessageHash(account.replaySafeHash(hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectRevert();
        account.isValidSignature(hash, abi.encode(GianoSmartWallet.SignatureWrapper(passkeyOwner, signature)));
    }

    /// @dev this case should not be possible, but we need to explicitly test the revert case
    function testRevertsIfOwnerIsInvalidEthereumAddress() public {
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 toSign = account.replaySafeHash(hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, toSign);
        bytes memory signature = abi.encodePacked(r, s, v);
        // 32 owner bytes that do not fit in an `address`. `addOwnerAddress`/`_initializeOwners`
        // make this unreachable, so force the entry straight into the `isOwner` mapping
        // (MUTLI_OWNABLE_STORAGE_LOCATION + 3) to reach the defensive revert.
        bytes memory invalidOwner = abi.encode(bytes32(uint256(type(uint160).max) + 1));
        bytes32 slot_isOwner =
            bytes32(uint256(0x0627f72af0e6f412195b0d8acbe438b28090dd545b7d2331fccf77723561f500) + 3);
        vm.store(address(account), keccak256(abi.encodePacked(invalidOwner, slot_isOwner)), bytes32(uint256(1)));
        assertTrue(account.isOwnerBytes(invalidOwner));

        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.InvalidEthereumAddressOwner.selector, invalidOwner));
        account.isValidSignature(hash, abi.encode(GianoSmartWallet.SignatureWrapper(invalidOwner, signature)));
    }
}
