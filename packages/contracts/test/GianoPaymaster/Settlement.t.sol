// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from 'forge-std/Vm.sol';
import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';

contract SettlementTest is PaymasterTestBase {
    address internal wallet = makeAddr('wallet');
    bytes32 internal constant OP_HASH = keccak256('op');

    uint256 internal constant EXECUTION_GAS_LIMIT = 300_000; // callGasLimit + paymasterPostOpGasLimit

    function setUp() public override {
        super.setUp();
        _fund(TENANT_A, 1 ether);
    }

    function _context(bytes16 tenantId, uint128 feeWei) internal view returns (bytes memory) {
        return abi.encode(tenantId, feeWei, EXECUTION_GAS_LIMIT, wallet, OP_HASH);
    }

    function _postOp(bytes memory ctx, IPaymaster.PostOpMode mode, uint256 gasCost, uint256 feePerGas) internal {
        vm.prank(address(ENTRY_POINT));
        paymaster.postOp(mode, ctx, gasCost, feePerGas);
    }

    // -----------------------------------------------------------------------------------------

    function test_postOp_revertsForAnyCallerOtherThanTheEntryPoint() public {
        vm.expectRevert(GianoPaymaster.NotEntryPoint.selector);
        vm.prank(outsider);
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, _context(TENANT_A, DEFAULT_FEE_WEI), 1, 1);
    }

    function test_postOp_debitsGasPlusFeePlusOverheadAndCreditsOnlyTheFee() public {
        uint256 before = paymaster.getTenant(TENANT_A).balance;
        uint256 gasCost = 0.002 ether;
        uint256 feePerGas = 2 gwei;
        uint256 overhead = _overheadWei(feePerGas, EXECUTION_GAS_LIMIT);

        _postOp(_context(TENANT_A, DEFAULT_FEE_WEI), IPaymaster.PostOpMode.opSucceeded, gasCost, feePerGas);

        assertEq(paymaster.getTenant(TENANT_A).balance, before - gasCost - overhead - DEFAULT_FEE_WEI);
        assertEq(paymaster.treasury(), DEFAULT_FEE_WEI, 'only the fee reaches the treasury');
        assertEq(paymaster.getTenant(TENANT_A).deficit, 0);
        _assertInvariant();
    }

    /// @dev The point of R-41: the overhead debit must *leave* the ledger. A charge that landed in
    ///      the treasury would cancel out of the ledger total and cover none of the deposit's own
    ///      extra drawdown, so the ledger would slowly come to promise more than the deposit holds.
    function test_postOp_overheadLeavesTheLedgerRatherThanMovingIntoTheTreasury() public {
        uint256 ledgerBefore = uint256(paymaster.getTenant(TENANT_A).balance) + paymaster.treasury();
        uint256 feePerGas = 3 gwei;
        uint256 overhead = _overheadWei(feePerGas, EXECUTION_GAS_LIMIT);

        _postOp(_context(TENANT_A, DEFAULT_FEE_WEI), IPaymaster.PostOpMode.opSucceeded, 0.001 ether, feePerGas);

        uint256 ledgerAfter = uint256(paymaster.getTenant(TENANT_A).balance) + paymaster.treasury();
        assertEq(ledgerAfter, ledgerBefore - 0.001 ether - overhead, 'the ledger must fall by gas + overhead');
    }

    function test_postOp_chargesTheFeeWhenTheUsersTransactionReverted() public {
        _postOp(_context(TENANT_A, DEFAULT_FEE_WEI), IPaymaster.PostOpMode.opReverted, 0.001 ether, 1 gwei);
        assertEq(paymaster.treasury(), DEFAULT_FEE_WEI, 'a reverted op still consumed the service');
    }

    function test_postOp_recordsTheSuccessFlagFromTheMode() public {
        vm.recordLogs();
        _postOp(_context(TENANT_A, DEFAULT_FEE_WEI), IPaymaster.PostOpMode.opReverted, 0.001 ether, 1 gwei);
        // last event is Sponsored; its final data word is `success`
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (, , , , bool success) = abi.decode(logs[logs.length - 1].data, (uint256, uint256, uint256, uint256, bool));
        assertFalse(success);
    }

    function test_postOp_chargesOverheadProportionalToTheExecutionGasLimit() public {
        // A client that grossly over-estimates its call gas is charged a proportionally larger
        // bound, because that over-estimate is exactly what drives the EntryPoint's penalty.
        uint256 feePerGas = 1 gwei;
        uint256 smallOverhead = _overheadWei(feePerGas, 100_000);
        uint256 largeOverhead = _overheadWei(feePerGas, 1_000_000);
        assertGt(largeOverhead, smallOverhead);

        uint256 before = paymaster.getTenant(TENANT_A).balance;
        vm.prank(address(ENTRY_POINT));
        paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            abi.encode(TENANT_A, uint128(0), uint256(1_000_000), wallet, OP_HASH),
            0,
            feePerGas
        );
        assertEq(paymaster.getTenant(TENANT_A).balance, before - largeOverhead);
    }

    // -----------------------------------------------------------------------------------------
    // Clamping and deficits
    // -----------------------------------------------------------------------------------------

    function test_postOp_clampsAtTheBalanceAndRecordsTheShortfall() public {
        _fund(TENANT_B, 0.001 ether);
        uint256 feePerGas = 1 gwei;
        uint256 overhead = _overheadWei(feePerGas, EXECUTION_GAS_LIMIT);
        uint256 gasCost = 0.01 ether;
        uint256 owed = gasCost + overhead + DEFAULT_FEE_WEI;

        vm.expectEmit(true, true, false, true, address(paymaster));
        emit GianoPaymaster.SponsorshipDeficit(TENANT_B, OP_HASH, owed - 0.001 ether, owed - 0.001 ether);
        _postOp(_context(TENANT_B, DEFAULT_FEE_WEI), IPaymaster.PostOpMode.opSucceeded, gasCost, feePerGas);

        assertEq(paymaster.getTenant(TENANT_B).balance, 0, 'clamped to zero, never negative');
        assertEq(paymaster.getTenant(TENANT_B).deficit, owed - 0.001 ether);
        _assertInvariant();
    }

    /// @dev Gas and overhead come out first, so a tenant that cannot cover everything pays the
    ///      network's costs before Giano's margin — the treasury is never funded at the expense of
    ///      money that has already left the deposit.
    function test_postOp_takesGasAndOverheadBeforeTheFee() public {
        uint256 feePerGas = 1 gwei;
        uint256 overhead = _overheadWei(feePerGas, EXECUTION_GAS_LIMIT);
        uint256 gasCost = 0.001 ether;
        // fund exactly gas + overhead + half the fee
        _fund(TENANT_B, gasCost + overhead + DEFAULT_FEE_WEI / 2);

        _postOp(_context(TENANT_B, DEFAULT_FEE_WEI), IPaymaster.PostOpMode.opSucceeded, gasCost, feePerGas);

        assertEq(paymaster.treasury(), DEFAULT_FEE_WEI / 2, 'only the recoverable part of the fee accrues');
        assertEq(paymaster.getTenant(TENANT_B).deficit, DEFAULT_FEE_WEI - DEFAULT_FEE_WEI / 2);
        assertEq(paymaster.getTenant(TENANT_B).balance, 0);
    }

    function test_postOp_neverRevertsOnAShortfall() public {
        // no balance at all — settlement must still complete, because the op already executed
        _postOp(_context(TENANT_B, DEFAULT_FEE_WEI), IPaymaster.PostOpMode.opSucceeded, 1 ether, 1 gwei);
        assertGt(paymaster.getTenant(TENANT_B).deficit, 0);
    }

    function test_postOp_accumulatesSuccessiveDeficits() public {
        _postOp(_context(TENANT_B, 0), IPaymaster.PostOpMode.opSucceeded, 1 ether, 0);
        uint256 first = paymaster.getTenant(TENANT_B).deficit;
        _postOp(_context(TENANT_B, 0), IPaymaster.PostOpMode.opSucceeded, 1 ether, 0);
        assertEq(paymaster.getTenant(TENANT_B).deficit, first * 2);
    }

    function test_depositFor_clearsTheDeficitBeforeCreditingTheBalance() public {
        _postOp(_context(TENANT_B, 0), IPaymaster.PostOpMode.opSucceeded, 0.5 ether, 0);
        uint256 deficit = paymaster.getTenant(TENANT_B).deficit;
        assertEq(deficit, 0.5 ether);

        _fund(TENANT_B, 0.75 ether);

        assertEq(paymaster.getTenant(TENANT_B).deficit, 0);
        assertEq(paymaster.getTenant(TENANT_B).balance, 0.25 ether);
        _assertInvariant();
    }

    function test_depositFor_partiallyClearsADeficitWithoutCreditingABalance() public {
        _postOp(_context(TENANT_B, 0), IPaymaster.PostOpMode.opSucceeded, 0.5 ether, 0);
        _fund(TENANT_B, 0.2 ether);

        assertEq(paymaster.getTenant(TENANT_B).deficit, 0.3 ether);
        assertEq(paymaster.getTenant(TENANT_B).balance, 0);
    }

    // -----------------------------------------------------------------------------------------
    // Fee pinning
    // -----------------------------------------------------------------------------------------

    /// @dev R-39: what an authorisation charges is fixed when it is issued. A rate change between
    ///      authorisation and settlement must not alter it in either direction.
    function test_postOp_chargesThePinnedFeeNotTheCurrentRate() public {
        uint128 pinned = DEFAULT_FEE_WEI;

        vm.prank(feeAdmin);
        paymaster.setDefaultFee(10 ether);

        _postOp(_context(TENANT_A, pinned), IPaymaster.PostOpMode.opSucceeded, 0.001 ether, 1 gwei);
        assertEq(paymaster.treasury(), pinned, 'the rate in force at authorisation is what is charged');
    }

    function test_feeFor_prefersATenantOverrideOverTheDefault() public {
        assertEq(paymaster.feeFor(TENANT_A), DEFAULT_FEE_WEI);

        vm.prank(feeAdmin);
        paymaster.setTenantFee(TENANT_A, true, 7 wei);
        assertEq(paymaster.feeFor(TENANT_A), 7);
        assertEq(paymaster.feeFor(TENANT_B), DEFAULT_FEE_WEI, 'other tenants are unaffected');

        vm.prank(feeAdmin);
        paymaster.setTenantFee(TENANT_A, false, 0);
        assertEq(paymaster.feeFor(TENANT_A), DEFAULT_FEE_WEI);
    }
}
