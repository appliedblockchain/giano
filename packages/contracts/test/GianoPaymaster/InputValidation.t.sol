// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';

/// @dev Every argument check on the administrative and funding paths, one test each. A zero
///      address or a zero amount is always a caller mistake, so the paymaster rejects it instead of
///      sending funds to nowhere or recording a no-op.
contract InputValidationTest is PaymasterTestBase {
    // -----------------------------------------------------------------------------------------
    // Tenant administration
    // -----------------------------------------------------------------------------------------

    /// @dev The zero id is the "no tenant" value, so it can never be registered.
    function test_registerTenant_rejectsTheZeroTenantId() public {
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.UnknownTenant.selector, bytes16(0)));
        vm.prank(tenantAdmin);
        paymaster.registerTenant(bytes16(0), tenantAWithdraw, 'zero');
    }

    function test_registerTenant_rejectsAZeroWithdrawAddress() public {
        vm.expectRevert(GianoPaymaster.ZeroAddress.selector);
        vm.prank(tenantAdmin);
        paymaster.registerTenant(bytes16(uint128(0xC0FFEE)), address(0), 'tenant-c');
    }

    /// @dev A second registration would overwrite the withdrawal address of a live tenant.
    function test_registerTenant_rejectsATenantThatIsAlreadyRegistered() public {
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.TenantAlreadyRegistered.selector, TENANT_A));
        vm.prank(tenantAdmin);
        paymaster.registerTenant(TENANT_A, outsider, 'tenant-a-again');

        assertEq(paymaster.getTenant(TENANT_A).withdrawAddress, tenantAWithdraw);
    }

    function test_setTenantWithdrawAddress_rejectsAZeroAddress() public {
        vm.expectRevert(GianoPaymaster.ZeroAddress.selector);
        vm.prank(withdrawAddressAdmin);
        paymaster.setTenantWithdrawAddress(TENANT_A, address(0));
    }

    // -----------------------------------------------------------------------------------------
    // Withdrawals
    // -----------------------------------------------------------------------------------------

    function test_withdrawTenant_rejectsAZeroRecipient() public {
        _fund(TENANT_A, 1 ether);
        vm.expectRevert(GianoPaymaster.ZeroAddress.selector);
        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 1 ether, address(0));
    }

    function test_withdrawTenant_rejectsAZeroAmount() public {
        _fund(TENANT_A, 1 ether);
        vm.expectRevert(GianoPaymaster.ZeroAmount.selector);
        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 0, tenantAWithdraw);
    }

    function test_withdrawFees_rejectsAZeroRecipient() public {
        vm.expectRevert(GianoPaymaster.ZeroAddress.selector);
        vm.prank(feeCollector);
        paymaster.withdrawFees(address(0), 1);
    }

    function test_withdrawFees_rejectsAZeroAmount() public {
        vm.expectRevert(GianoPaymaster.ZeroAmount.selector);
        vm.prank(feeCollector);
        paymaster.withdrawFees(feeCollector, 0);
    }

    function test_withdrawStake_rejectsAZeroRecipient() public {
        vm.expectRevert(GianoPaymaster.ZeroAddress.selector);
        vm.prank(stakeAdmin);
        paymaster.withdrawStake(payable(address(0)));
    }

    // -----------------------------------------------------------------------------------------
    // Signers
    // -----------------------------------------------------------------------------------------

    /// @dev `ecrecover` returns the zero address for a malformed signature, so a zero signer would
    ///      accept garbage.
    function test_addSigner_rejectsTheZeroAddress() public {
        vm.expectRevert(GianoPaymaster.ZeroAddress.selector);
        vm.prank(signerAdmin);
        paymaster.addSigner(address(0));
    }

    // -----------------------------------------------------------------------------------------
    // Views
    // -----------------------------------------------------------------------------------------

    function test_signerAt_readsTheSignerSetByIndex() public {
        address second = makeAddr('secondSigner');
        vm.prank(signerAdmin);
        paymaster.addSigner(second);

        assertEq(paymaster.signerAt(0), sponsor);
        assertEq(paymaster.signerAt(1), second);
    }

    function test_getDeposit_matchesTheEntryPointBalance() public {
        assertEq(paymaster.getDeposit(), 0);
        _fund(TENANT_A, 1 ether);
        assertEq(paymaster.getDeposit(), 1 ether);
        assertEq(paymaster.getDeposit(), ENTRY_POINT.balanceOf(address(paymaster)));
    }
}
