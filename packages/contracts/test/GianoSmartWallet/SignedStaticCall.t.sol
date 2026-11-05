// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import './SmartWalletTestBase.sol';
import {AuthenticatedStaticCaller, StaticCall} from '../../src/AuthenticatedStaticCaller.sol';

/// @dev A view that answers only its owner, like `PrivateERC20.privateBalanceOf`.
contract GatedView {
    error Unauthorized(address caller);

    address public immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function secret(uint256 id) external view returns (uint256) {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        return id * 2;
    }
}

contract TestSignedStaticCall is SmartWalletTestBase {
    /// @dev A fixed start time. Under via-ir, a local copy of `block.timestamp` can read the warped value.
    uint256 constant START = 1_800_000_000;

    GatedView gated;
    GatedView otherGated;

    function setUp() public override {
        super.setUp();
        gated = new GatedView(address(account));
        otherGated = new GatedView(address(account));
        vm.warp(START);
    }

    function _signStaticCall(address target, bytes memory data, uint256 signedAt) internal view returns (bytes memory) {
        bytes32 hash = account.staticCallHash(target, data, signedAt);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, account.replaySafeHash(hash));
        return abi.encode(GianoSmartWallet.SignatureWrapper(abi.encode(signer), abi.encodePacked(r, s, v)));
    }

    function _call(address target, bytes memory data, uint256 signedAt, bytes memory signature)
        internal
        view
        returns (bytes memory)
    {
        return account.signedStaticCall(StaticCall({target: target, data: data, signedAt: signedAt, signature: signature}));
    }

    function testStaticCallHashCoversTargetAndCalldata() public view {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        bytes32 expected = keccak256(
            abi.encode(AuthenticatedStaticCaller.signedStaticCall.selector, block.timestamp, address(gated), keccak256(data))
        );
        assertEq(account.staticCallHash(address(gated), data, block.timestamp), expected);
    }

    /// @dev The same vector is checked in wallet-core `account.test.ts`, so the SDK and the
    ///      contract hash the same structure.
    function testStaticCallHashMatchesTheSdkVector() public view {
        assertEq(
            account.staticCallHash(address(0x1111111111111111111111111111111111111111), hex'abcd', 1_800_000_000),
            0x3d2dbb74c0df8af655710f6b6dc62ea5d3e26f53e8b52a74ebda5bb44d988e4c
        );
    }

    function testRunsTheSignedCallAsTheWallet() public view {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        bytes memory signature = _signStaticCall(address(gated), data, block.timestamp);

        bytes memory result = _call(address(gated), data, block.timestamp, signature);
        assertEq(abi.decode(result, (uint256)), 42);
    }

    /// @dev The SDK tells the wallet's errors from a target's by selector, so a target's revert
    ///      must reach the caller unchanged.
    function testPassesATargetRevertThroughUnchanged() public {
        GatedView foreign = new GatedView(address(0xdead));
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        bytes memory signature = _signStaticCall(address(foreign), data, block.timestamp);

        vm.expectRevert(abi.encodeWithSelector(GatedView.Unauthorized.selector, address(account)));
        _call(address(foreign), data, block.timestamp, signature);
    }

    function testRejectsTheSignatureForOtherCalldata() public {
        bytes memory signedData = abi.encodeCall(GatedView.secret, (21));
        bytes memory signature = _signStaticCall(address(gated), signedData, block.timestamp);

        vm.expectRevert(AuthenticatedStaticCaller.StaticCallInvalidSignature.selector);
        _call(address(gated), abi.encodeCall(GatedView.secret, (22)), block.timestamp, signature);
    }

    function testRejectsTheSignatureForAnotherTarget() public {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        bytes memory signature = _signStaticCall(address(gated), data, block.timestamp);

        vm.expectRevert(AuthenticatedStaticCaller.StaticCallInvalidSignature.selector);
        _call(address(otherGated), data, block.timestamp, signature);
    }

    function testRejectsTheSignatureForAnotherSignedAt() public {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        bytes memory signature = _signStaticCall(address(gated), data, block.timestamp);

        vm.expectRevert(AuthenticatedStaticCaller.StaticCallInvalidSignature.selector);
        _call(address(gated), data, block.timestamp - 1, signature);
    }

    /// @dev The old hash covered only the selector and `signedAt`. A signature over it must not
    ///      authorise any call now.
    function testRejectsTheOldBlanketSignature() public {
        bytes32 oldHash = keccak256(
            bytes.concat(AuthenticatedStaticCaller.signedStaticCall.selector, bytes32(block.timestamp))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, account.replaySafeHash(oldHash));
        bytes memory signature =
            abi.encode(GianoSmartWallet.SignatureWrapper(abi.encode(signer), abi.encodePacked(r, s, v)));

        vm.expectRevert(AuthenticatedStaticCaller.StaticCallInvalidSignature.selector);
        _call(address(gated), abi.encodeCall(GatedView.secret, (21)), block.timestamp, signature);
    }

    function testRejectsAFutureSignedAt() public {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        uint256 signedAt = block.timestamp + 1;
        bytes memory signature = _signStaticCall(address(gated), data, signedAt);

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthenticatedStaticCaller.StaticCallSignatureNotYetValid.selector, signedAt, block.timestamp
            )
        );
        _call(address(gated), data, signedAt, signature);
    }

    function testAcceptsTheSignatureUntilTheEndOfItsLifetime() public {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        uint256 signedAt = START;
        bytes memory signature = _signStaticCall(address(gated), data, signedAt);

        vm.warp(signedAt + account.getSignatureLifetime());
        assertEq(abi.decode(_call(address(gated), data, signedAt, signature), (uint256)), 42);
    }

    function testRejectsAnExpiredSignature() public {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        uint256 signedAt = START;
        bytes memory signature = _signStaticCall(address(gated), data, signedAt);
        uint256 expiredAt = signedAt + account.getSignatureLifetime();

        vm.warp(expiredAt + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthenticatedStaticCaller.StaticCallSignatureExpired.selector, expiredAt, expiredAt + 1
            )
        );
        _call(address(gated), data, signedAt, signature);
    }

    function testRejectsASignatureFromANonOwner() public {
        bytes memory data = abi.encodeCall(GatedView.secret, (21));
        bytes32 hash = account.staticCallHash(address(gated), data, block.timestamp);
        uint256 strangerKey = 0xb0b;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(strangerKey, account.replaySafeHash(hash));
        bytes memory signature = abi.encode(
            GianoSmartWallet.SignatureWrapper(abi.encode(vm.addr(strangerKey)), abi.encodePacked(r, s, v))
        );

        vm.expectRevert(AuthenticatedStaticCaller.StaticCallInvalidSignature.selector);
        _call(address(gated), data, block.timestamp, signature);
    }
}
