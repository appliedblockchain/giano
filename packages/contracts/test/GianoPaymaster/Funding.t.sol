// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {IStakeManager} from '@account-abstraction/contracts/interfaces/IStakeManager.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';

contract FundingTest is PaymasterTestBase {
    // -----------------------------------------------------------------------------------------
    // Funding
    // -----------------------------------------------------------------------------------------

    function test_depositFor_creditsTheTenantAndTheDeposit() public {
        vm.expectEmit(true, true, false, true, address(paymaster));
        emit GianoPaymaster.TenantFunded(TENANT_A, address(this), 1 ether, 0, 1 ether);
        _fund(TENANT_A, 1 ether);

        assertEq(paymaster.getTenant(TENANT_A).balance, 1 ether);
        assertEq(ENTRY_POINT.balanceOf(address(paymaster)), 1 ether);
        _assertInvariant();
    }

    function test_depositFor_isTheOnlyWayFundsArriveSoNothingIsUnattributed() public {
        vm.deal(outsider, 1 ether);
        // A raw call rather than `transfer`: the 2300-gas stipend would swallow the revert reason,
        // and the point of the test is that the refusal is legible.
        vm.prank(outsider);
        (bool ok, bytes memory reason) = payable(address(paymaster)).call{value: 1 ether}('');
        assertFalse(ok);
        assertEq(bytes4(reason), GianoPaymaster.DirectTransferNotAllowed.selector);
        assertEq(ENTRY_POINT.balanceOf(address(paymaster)), 0);
    }

    function test_depositFor_revertsForAnUnregisteredTenant() public {
        bytes16 unknown = bytes16(uint128(0xFEED));
        vm.deal(address(this), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.UnknownTenant.selector, unknown));
        paymaster.depositFor{value: 1 ether}(unknown);
    }

    function test_depositFor_revertsOnAZeroValueCall() public {
        vm.expectRevert(GianoPaymaster.ZeroAmount.selector);
        paymaster.depositFor{value: 0}(TENANT_A);
    }

    /// @dev Anyone may fund a tenant — R-30 requires attribution, not a particular payer, and Q4
    ///      leaves the commercial arrangement open.
    function test_depositFor_acceptsFundingFromAnyAddress() public {
        vm.deal(outsider, 1 ether);
        vm.prank(outsider);
        paymaster.depositFor{value: 1 ether}(TENANT_A);
        assertEq(paymaster.getTenant(TENANT_A).balance, 1 ether);
    }

    function test_depositFor_keepsTenantBalancesSeparate() public {
        _fund(TENANT_A, 1 ether);
        _fund(TENANT_B, 3 ether);
        assertEq(paymaster.getTenant(TENANT_A).balance, 1 ether);
        assertEq(paymaster.getTenant(TENANT_B).balance, 3 ether);
        assertEq(ENTRY_POINT.balanceOf(address(paymaster)), 4 ether);
    }

    // -----------------------------------------------------------------------------------------
    // Tenant withdrawal
    // -----------------------------------------------------------------------------------------

    function test_withdrawTenant_movesFundsToTheTenantsChosenAddress() public {
        _fund(TENANT_A, 1 ether);
        address recipient = makeAddr('recipient');

        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 0.4 ether, recipient);

        assertEq(recipient.balance, 0.4 ether);
        assertEq(paymaster.getTenant(TENANT_A).balance, 0.6 ether);
        assertEq(ENTRY_POINT.balanceOf(address(paymaster)), 0.6 ether);
        _assertInvariant();
    }

    function test_withdrawTenant_isRefusedForAnyOtherCaller() public {
        _fund(TENANT_A, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.NotWithdrawAddress.selector, TENANT_A, tenantBWithdraw));
        vm.prank(tenantBWithdraw);
        paymaster.withdrawTenant(TENANT_A, 1, tenantBWithdraw);
    }

    function test_withdrawTenant_cannotOverdraw() public {
        _fund(TENANT_A, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.InsufficientTenantBalance.selector, TENANT_A, 2 ether, 1 ether));
        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 2 ether, tenantAWithdraw);
    }

    /// @dev One tenant's withdrawal address must not reach another tenant's money even though both
    ///      balances sit in the same deposit.
    function test_withdrawTenant_cannotReachAnotherTenantsBalance() public {
        _fund(TENANT_A, 1 ether);
        _fund(TENANT_B, 1 ether);

        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.NotWithdrawAddress.selector, TENANT_B, tenantAWithdraw));
        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_B, 1 ether, tenantAWithdraw);
    }

    /// @dev R-53. A pause halts new sponsorship; it must never trap a tenant's funds.
    function test_withdrawTenant_worksWhileThePaymasterIsPaused() public {
        _fund(TENANT_A, 1 ether);
        vm.prank(pauser);
        paymaster.pause();

        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 1 ether, tenantAWithdraw);
        assertEq(tenantAWithdraw.balance, 1 ether);
    }

    function test_setTenantWithdrawAddress_movesTheExit() public {
        _fund(TENANT_A, 1 ether);
        address newExit = makeAddr('newExit');

        vm.prank(tenantAdmin);
        paymaster.setTenantWithdrawAddress(TENANT_A, newExit);

        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.NotWithdrawAddress.selector, TENANT_A, tenantAWithdraw));
        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 1, tenantAWithdraw);

        vm.prank(newExit);
        paymaster.withdrawTenant(TENANT_A, 1 ether, newExit);
        assertEq(newExit.balance, 1 ether);
    }

    // -----------------------------------------------------------------------------------------
    // Fee withdrawal
    // -----------------------------------------------------------------------------------------

    function test_withdrawFees_isCappedAtWhatHasAccrued() public {
        _fund(TENANT_A, 1 ether);
        _accrueFees(0.01 ether);

        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.ExceedsTreasury.selector, 0.02 ether, 0.01 ether));
        vm.prank(feeCollector);
        paymaster.withdrawFees(feeCollector, 0.02 ether);

        vm.prank(feeCollector);
        paymaster.withdrawFees(feeCollector, 0.01 ether);
        assertEq(feeCollector.balance, 0.01 ether);
        assertEq(paymaster.treasury(), 0);
        _assertInvariant();
    }

    function _accrueFees(uint128 amount) internal {
        vm.prank(address(ENTRY_POINT));
        paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            abi.encode(TENANT_A, amount, uint256(0), address(0), bytes32(0)),
            0,
            0
        );
    }

    // -----------------------------------------------------------------------------------------
    // Stake
    // -----------------------------------------------------------------------------------------

    /// @dev R-24: a paymaster that is deployed but not staked fails in a way that looks like a
    ///      client bug, so the deployment sequence stakes it and `giano-doctor` asserts it.
    function test_stakeIsHeldSeparatelyFromTheDeposit() public {
        _fund(TENANT_A, 1 ether);
        _stake();

        IStakeManager.DepositInfo memory info = ENTRY_POINT.getDepositInfo(address(paymaster));
        assertEq(info.stake, 1 ether);
        assertEq(info.deposit, 1 ether, 'staking must not touch the deposit');
        assertTrue(info.staked);
        _assertInvariant();
    }

    function test_stakeAdminCannotReachTheDepositThroughUnstaking() public {
        _fund(TENANT_A, 1 ether);
        _stake();

        vm.prank(stakeAdmin);
        paymaster.unlockStake();
        vm.warp(block.timestamp + 2 days);
        vm.prank(stakeAdmin);
        paymaster.withdrawStake(payable(stakeAdmin));

        assertEq(stakeAdmin.balance, 2 ether, 'the 1 ether left over from _stake plus the stake back');
        assertEq(ENTRY_POINT.balanceOf(address(paymaster)), 1 ether, 'the deposit is untouched');
        _assertInvariant();
    }
}

