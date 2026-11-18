// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {SenderCreator} from '@account-abstraction/contracts/core/SenderCreator.sol';
import {IEntryPoint} from '@account-abstraction/contracts/interfaces/IEntryPoint.sol';
import {PackedUserOperation} from '@account-abstraction/contracts/interfaces/PackedUserOperation.sol';
import {FCL_ecdsa} from 'FreshCryptoLib/FCL_ecdsa.sol';
import {Test, console2} from 'forge-std/Test.sol';
import {WebAuthn} from 'webauthn-sol/WebAuthn.sol';
import 'webauthn-sol/../test/Utils.sol';

import {GianoSmartWallet} from '../../src/GianoSmartWallet.sol';
import {GianoSmartWalletFactory} from '../../src/GianoSmartWalletFactory.sol';
import {Static} from './Static.sol';

/// @dev The verification gas of a passkey wallet's first operation, through the canonical EntryPoint
///      v0.9: the wallet's deployment by the factory, then its WebAuthn validation, with the prefund
///      paid by the wallet itself (the most expensive case). Giano's wallet sends 800,000 verification
///      gas for a passkey (`toGianoSmartAccount`'s `estimateGas` hook), and viem keeps it over the
///      bundler's estimate. On a chain that cannot simulate (`bundler.stateOverride: false`) nothing
///      checks it before submission, so this test does. It must also fit on a chain without the
///      P-256 precompile, where WebAuthn falls back to FreshCryptoLib.
contract FirstOperationGasTest is Test {
    /// @dev The verification gas Giano's wallet sends for a passkey (`toGianoSmartAccount.ts`).
    uint256 internal constant WALLET_VERIFICATION_GAS = 800_000;
    /// @dev Room left under it for a longer `clientDataJSON` than this test's and for compiler changes.
    uint256 internal constant HEADROOM = 100_000;
    uint256 internal constant CALL_GAS = 100_000;
    uint256 internal constant FEE = 1 gwei;

    IEntryPoint internal constant ENTRY_POINT = IEntryPoint(0x433709009B8330FDa32311DF1C2AFA402eD8D009);
    address internal constant P256_VERIFIER = address(0x100);

    uint256 internal passkeyPrivateKey = uint256(0x03d99692017473e2d631945a812607b23269d85721e0f370b8d3e7d29a874fd2);
    bytes internal passkeyOwner =
        hex'1c05286fe694493eae33312f2d2e0d0abeda8db76238b7a204be1fb87f54ce4228fef61ef4ac300f631657635c28e59bfb2fe71bce1634c81c65642042f6dc4d';
    address internal bundler = makeAddr('bundler');

    GianoSmartWalletFactory internal factory;
    bytes[] internal owners;
    address internal sender;

    function setUp() public {
        vm.etch(address(ENTRY_POINT), Static.ENTRY_POINT_BYTES);
        // The etched runtime points at the SenderCreator the canonical deployment created; it must
        // exist, and accept calls from the EntryPoint only.
        vm.prank(address(ENTRY_POINT));
        SenderCreator senderCreator = new SenderCreator();
        vm.etch(address(ENTRY_POINT.senderCreator()), address(senderCreator).code);

        factory = new GianoSmartWalletFactory(address(new GianoSmartWallet()));
        owners.push(passkeyOwner);
        sender = factory.getAddress(owners, 0);
        vm.deal(sender, 1 ether);
    }

    function test_gas_firstPasskeyOperationFitsTheWalletsVerificationGas() public {
        uint256 lowest = _lowestVerificationGas();
        (uint256 withoutPrecompile, bool precompile) = _withoutPrecompile(lowest);

        console2.log('first passkey operation, lowest verification gas', lowest);
        console2.log('P-256 precompile in this EVM', precompile);
        console2.log('the same without the P-256 precompile (FreshCryptoLib)', withoutPrecompile);

        assertLt(lowest + HEADROOM, WALLET_VERIFICATION_GAS, 'a first passkey operation no longer fits 800,000');
        assertLt(
            withoutPrecompile + HEADROOM,
            WALLET_VERIFICATION_GAS,
            'without the P-256 precompile, a first passkey operation no longer fits 800,000'
        );
        assertTrue(_passes(WALLET_VERIFICATION_GAS), 'the wallet value itself must pass');
    }

    /// @dev The lowest verification gas limit at which the EntryPoint accepts the operation.
    function _lowestVerificationGas() internal returns (uint256 low) {
        uint256 high = 2_000_000;
        low = 50_000;
        require(_passes(high) && !_passes(low), 'search bounds');
        while (high - low > 1_000) {
            uint256 mid = (low + high) / 2;
            if (_passes(mid)) high = mid;
            else low = mid;
        }
        return high;
    }

    /// @dev Where this EVM has the P-256 precompile, WebAuthn used it; on a chain without it,
    ///      WebAuthn's call to 0x100 returns nothing and FreshCryptoLib verifies instead.
    function _withoutPrecompile(uint256 lowest) internal view returns (uint256, bool) {
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(keccak256('gas'));
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        (uint256 x, uint256 y) = abi.decode(passkeyOwner, (uint256, uint256));

        (, bytes memory answer) = P256_VERIFIER.staticcall(abi.encode(webAuthn.messageHash, r, s, x, y));
        bool precompile = answer.length == 32;
        if (!precompile) return (lowest, false);

        uint256 before = gasleft();
        bool valid = FCL_ecdsa.ecdsa_verify(webAuthn.messageHash, uint256(r), uint256(s), x, y);
        uint256 fcl = before - gasleft();
        assertTrue(valid, 'FreshCryptoLib must accept the signature');
        // The precompile's own cost stays counted in `lowest`: this errs high.
        return (lowest + fcl, true);
    }

    function _passes(uint256 verificationGasLimit) internal returns (bool ok) {
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = _signedOp(verificationGasLimit);
        uint256 state = vm.snapshotState();
        vm.prank(bundler, bundler);
        try ENTRY_POINT.handleOps(ops, payable(bundler)) {
            ok = sender.code.length > 0;
        } catch {
            ok = false;
        }
        vm.revertToState(state);
    }

    function _signedOp(uint256 verificationGasLimit) internal view returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: abi.encodePacked(address(factory), abi.encodeCall(GianoSmartWalletFactory.createAccount, (owners, 0))),
            callData: abi.encodeCall(GianoSmartWallet.execute, (address(0xdead), 0, '')),
            accountGasLimits: bytes32((verificationGasLimit << 128) | CALL_GAS),
            preVerificationGas: 0,
            gasFees: bytes32((FEE << 128) | FEE),
            paymasterAndData: '',
            signature: ''
        });
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(ENTRY_POINT.getUserOpHash(op));
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        op.signature = abi.encode(
            GianoSmartWallet.SignatureWrapper({
                ownerBytes: passkeyOwner,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: Utils.normalizeS(uint256(s))
                    })
                )
            })
        );
    }
}
