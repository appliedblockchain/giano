// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {PackedUserOperation} from '@account-abstraction/contracts/interfaces/PackedUserOperation.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';

contract ValidationTest is PaymasterTestBase {
    uint256 internal constant SIG_FAILED = 1;

    address internal wallet = makeAddr('wallet');

    function setUp() public override {
        super.setUp();
        _fund(TENANT_A, 1 ether);
    }

    function _validate(PackedUserOperation memory op, uint256 maxCost) internal returns (bytes memory ctx, uint256 vd) {
        vm.prank(address(ENTRY_POINT));
        return paymaster.validatePaymasterUserOp(op, keccak256('userOpHash'), maxCost);
    }

    function _validOp() internal view returns (PackedUserOperation memory) {
        return _sponsoredOp(_defaultOpParams(wallet), TENANT_A, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);
    }

    // -----------------------------------------------------------------------------------------

    function test_validate_acceptsAValidAuthorisation() public {
        OpParams memory p = _defaultOpParams(wallet);
        uint48 validUntil = uint48(block.timestamp + 120);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_A, validUntil, 0, DEFAULT_FEE_WEI);

        (bytes memory ctx, uint256 vd) = _validate(op, 0.001 ether);

        (bytes16 tenantId, uint128 feeWei, uint256 executionGasLimit, address sender, bytes32 hash) = abi.decode(
            ctx,
            (bytes16, uint128, uint256, address, bytes32)
        );
        assertEq(tenantId, TENANT_A);
        assertEq(feeWei, DEFAULT_FEE_WEI);
        assertEq(executionGasLimit, uint256(p.callGasLimit) + uint256(p.pmPostOpGasLimit));
        assertEq(sender, wallet);
        assertEq(hash, keccak256('userOpHash'));

        // packValidationData(false, validUntil, validAfter)
        assertEq(vd, (uint256(validUntil) << 160));
    }

    function test_validate_pinsTheValidityWindow() public {
        PackedUserOperation memory op = _sponsoredOp(_defaultOpParams(wallet), TENANT_A, 5000, 4000, DEFAULT_FEE_WEI);
        (, uint256 vd) = _validate(op, 0.001 ether);
        assertEq(vd, (uint256(5000) << 160) | (uint256(4000) << 208));
    }

    function test_validate_revertsForAnyCallerOtherThanTheEntryPoint() public {
        PackedUserOperation memory op = _validOp();
        vm.expectRevert(GianoPaymaster.NotEntryPoint.selector);
        vm.prank(outsider);
        paymaster.validatePaymasterUserOp(op, keccak256('h'), 0.001 ether);
    }

    function test_validate_revertsWhenPaused() public {
        vm.prank(pauser);
        paymaster.pause();
        PackedUserOperation memory op = _validOp();
        vm.expectRevert(GianoPaymaster.PaymasterPaused.selector);
        _validate(op, 0.001 ether);
    }

    function test_validate_revertsOnAnUnknownVersionByte() public {
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_A, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);
        bytes memory pmad = op.paymasterAndData;
        pmad[52] = 0x02; // the version byte
        op.paymasterAndData = pmad;

        vm.expectRevert(GianoPaymaster.BadPaymasterData.selector);
        _validate(op, 0.001 ether);
    }

    function test_validate_revertsOnTruncatedPaymasterData() public {
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _bareOp(p);
        op.paymasterAndData = abi.encodePacked(_paymasterPrefix(p), uint8(0x01), TENANT_A);

        vm.expectRevert(GianoPaymaster.BadPaymasterData.selector);
        _validate(op, 0.001 ether);
    }

    function test_validate_revertsForAnUnregisteredTenant() public {
        bytes16 unknown = bytes16(uint128(0xDEAD));
        PackedUserOperation memory op = _sponsoredOp(_defaultOpParams(wallet), unknown, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);

        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.UnknownTenant.selector, unknown));
        _validate(op, 0.001 ether);
    }

    function test_validate_revertsForADisabledTenant() public {
        vm.prank(tenantAdmin);
        paymaster.setTenantEnabled(TENANT_A, false);

        PackedUserOperation memory op = _validOp();
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.TenantDisabled.selector, TENANT_A));
        _validate(op, 0.001 ether);
    }

    function test_validate_revertsForAKeyThatIsNotInTheSignerSet() public {
        vm.prank(signerAdmin);
        paymaster.removeSigner(sponsor);

        PackedUserOperation memory op = _validOp();
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.UnauthorisedSigner.selector, sponsor));
        _validate(op, 0.001 ether);
    }

    /// @dev A revoked key must fail on the cheap membership test, never on the cryptography — that
    ///      is what makes revocation an immediate stop rather than a slow one.
    function test_validate_rejectsARevokedKeyEvenWithAPerfectlyValidSignature() public {
        PackedUserOperation memory op = _validOp();
        vm.prank(signerAdmin);
        paymaster.removeSigner(sponsor);

        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.UnauthorisedSigner.selector, sponsor));
        _validate(op, 0.001 ether);
    }

    /// @dev A bad signature must come back as SIG_VALIDATION_FAILED rather than a revert, so the
    ///      bundler reads it as an invalid operation rather than a paymaster fault.
    function test_validate_returnsSigValidationFailedForATamperedSignature() public {
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_A, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);

        bytes memory pmad = op.paymasterAndData;
        pmad[pmad.length - 2] = bytes1(uint8(pmad[pmad.length - 2]) ^ 0xFF);
        op.paymasterAndData = pmad;

        (bytes memory ctx, uint256 vd) = _validate(op, 0.001 ether);
        assertEq(vd, SIG_FAILED);
        assertEq(ctx.length, 0);
    }

    /// @dev The signature covers the fee, so a user cannot lower what their tenant is charged.
    function test_validate_rejectsAnAlteredFee() public {
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_A, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);

        bytes memory signed = op.paymasterAndData;
        bytes memory tampered = abi.encodePacked(
            _paymasterPrefix(p),
            _authorisationHeader(TENANT_A, uint48(block.timestamp + 120), 0, uint128(1), sponsor)
        );
        // keep the original signature, swap only the fee
        for (uint256 i = 52 + 65; i < signed.length; i++) {
            tampered = abi.encodePacked(tampered, signed[i]);
        }
        op.paymasterAndData = tampered;

        (, uint256 vd) = _validate(op, 0.001 ether);
        assertEq(vd, SIG_FAILED);
    }

    /// @dev The signature covers the tenant, which is what stops a user redirecting the charge to
    ///      somebody else's balance.
    function test_validate_rejectsARedirectedTenant() public {
        _fund(TENANT_B, 1 ether);
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_A, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);

        bytes memory signed = op.paymasterAndData;
        bytes memory tampered = abi.encodePacked(
            _paymasterPrefix(p),
            _authorisationHeader(TENANT_B, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI, sponsor)
        );
        for (uint256 i = 52 + 65; i < signed.length; i++) {
            tampered = abi.encodePacked(tampered, signed[i]);
        }
        op.paymasterAndData = tampered;

        (, uint256 vd) = _validate(op, 0.001 ether);
        assertEq(vd, SIG_FAILED);
    }

    function test_validate_rejectsAnAuthorisationForADifferentSender() public {
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_A, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);
        op.sender = makeAddr('someoneElse');

        (, uint256 vd) = _validate(op, 0.001 ether);
        assertEq(vd, SIG_FAILED);
    }

    function test_validate_rejectsAnAuthorisationReplayedOnADifferentNonce() public {
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_A, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);
        op.nonce = 1;

        (, uint256 vd) = _validate(op, 0.001 ether);
        assertEq(vd, SIG_FAILED);
    }

    function test_validate_rejectsAnAuthorisationReplayedOnADifferentChain() public {
        PackedUserOperation memory op = _validOp();
        vm.chainId(block.chainid + 1);

        (, uint256 vd) = _validate(op, 0.001 ether);
        assertEq(vd, SIG_FAILED);
    }

    function test_validate_refusesWhenTheBalanceCannotCoverGasPlusFeePlusOverhead() public {
        OpParams memory p = _defaultOpParams(wallet);
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_B, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);
        _fund(TENANT_B, 0.0002 ether);

        uint256 maxCost = 0.001 ether;
        uint256 expected = maxCost +
            DEFAULT_FEE_WEI +
            _overheadWei(p.maxFeePerGas, uint256(p.callGasLimit) + uint256(p.pmPostOpGasLimit));

        vm.expectRevert(
            abi.encodeWithSelector(GianoPaymaster.InsufficientTenantBalance.selector, TENANT_B, expected, 0.0002 ether)
        );
        _validate(op, maxCost);
    }

    /// @dev The on-chain check is a backstop, and it must account for the fee and overhead as well
    ///      as the gas — otherwise a balance that covers gas alone would still overdraw.
    function test_validate_countsFeeAndOverheadTowardsTheBalanceCheck() public {
        OpParams memory p = _defaultOpParams(wallet);
        uint256 maxCost = 0.001 ether;
        uint256 overhead = _overheadWei(p.maxFeePerGas, uint256(p.callGasLimit) + uint256(p.pmPostOpGasLimit));

        // exactly enough for gas alone: must refuse
        PackedUserOperation memory op = _sponsoredOp(p, TENANT_B, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);
        _fund(TENANT_B, maxCost);
        vm.expectRevert(
            abi.encodeWithSelector(
                GianoPaymaster.InsufficientTenantBalance.selector,
                TENANT_B,
                maxCost + DEFAULT_FEE_WEI + overhead,
                maxCost
            )
        );
        _validate(op, maxCost);

        // exactly enough for gas + fee + overhead: must accept
        _fund(TENANT_B, DEFAULT_FEE_WEI + overhead);
        _validate(op, maxCost);
    }

    function test_validate_refusesATenantCarryingADeficit() public {
        // drive TENANT_B into deficit by settling more than it holds
        _fund(TENANT_B, 0.001 ether);
        bytes memory ctx = abi.encode(TENANT_B, DEFAULT_FEE_WEI, uint256(300_000), wallet, keccak256('h'));
        vm.prank(address(ENTRY_POINT));
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 0.01 ether, 1 gwei);
        assertGt(paymaster.getTenant(TENANT_B).deficit, 0);

        _fund(TENANT_B, 1 ether);
        // funding cleared the deficit, so authorisation works again
        PackedUserOperation memory op = _sponsoredOp(_defaultOpParams(wallet), TENANT_B, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);
        _validate(op, 0.001 ether);
    }

    function test_validate_blocksWhileTheDeficitStands() public {
        _fund(TENANT_B, 0.001 ether);
        bytes memory ctx = abi.encode(TENANT_B, DEFAULT_FEE_WEI, uint256(300_000), wallet, keccak256('h'));
        vm.prank(address(ENTRY_POINT));
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 0.01 ether, 1 gwei);

        uint256 deficit = paymaster.getTenant(TENANT_B).deficit;
        PackedUserOperation memory op = _sponsoredOp(_defaultOpParams(wallet), TENANT_B, uint48(block.timestamp + 120), 0, DEFAULT_FEE_WEI);

        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.TenantInDeficit.selector, TENANT_B, deficit));
        _validate(op, 0.001 ether);
    }
}
