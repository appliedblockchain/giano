// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccessControl} from '@openzeppelin/contracts/access/IAccessControl.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';

contract RolesTest is PaymasterTestBase {
    function _expectUnauthorised(address caller, bytes32 role) internal {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, caller, role));
        vm.prank(caller);
    }

    // -----------------------------------------------------------------------------------------
    // No owner, no superuser
    // -----------------------------------------------------------------------------------------

    /// @dev R-44. `DEFAULT_ADMIN_ROLE` is OpenZeppelin's implicit superuser; the initialiser never
    ///      grants it, and every role is administered by ROLE_ADMIN instead.
    function test_theDefaultAdminRoleIsHeldByNobody() public view {
        assertEq(paymaster.getRoleMemberCount(0x00), 0);
    }

    function test_everyRoleIsAdministeredByRoleAdmin() public view {
        bytes32 roleAdminRole = paymaster.ROLE_ADMIN();
        assertEq(paymaster.getRoleAdmin(paymaster.ROLE_ADMIN()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.SIGNER_ADMIN_ROLE()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.FEE_ADMIN_ROLE()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.FEE_COLLECTOR_ROLE()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.STAKE_ADMIN_ROLE()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.TENANT_ADMIN_ROLE()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.PARAM_ADMIN_ROLE()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.PAUSER_ROLE()), roleAdminRole);
        assertEq(paymaster.getRoleAdmin(paymaster.UPGRADER_ROLE()), roleAdminRole);
    }

    function test_exactlyOneAccountHoldsRoleAdmin() public view {
        assertEq(paymaster.getRoleMemberCount(paymaster.ROLE_ADMIN()), 1);
        assertEq(paymaster.getRoleMember(paymaster.ROLE_ADMIN(), 0), roleAdmin);
    }

    /// @dev The heart of R-46: a role holder cannot promote itself, because the only account that
    ///      can grant anything is ROLE_ADMIN — a timelock in a real deployment.
    function test_aRoleHolderCannotGrantItselfAnotherRole() public {
        // Read the role first: an external call made after `expectRevert` is armed would consume it.
        bytes32 target = paymaster.FEE_COLLECTOR_ROLE();
        _expectUnauthorised(feeAdmin, paymaster.ROLE_ADMIN());
        paymaster.grantRole(target, feeAdmin);
    }

    function test_anOutsiderCannotGrantAnything() public {
        bytes32 target = paymaster.PAUSER_ROLE();
        _expectUnauthorised(outsider, paymaster.ROLE_ADMIN());
        paymaster.grantRole(target, outsider);
    }

    // -----------------------------------------------------------------------------------------
    // Every privileged function is gated, and gated by the right role
    // -----------------------------------------------------------------------------------------

    function test_signerAdministrationIsGated() public {
        _expectUnauthorised(outsider, paymaster.SIGNER_ADMIN_ROLE());
        paymaster.addSigner(outsider);

        _expectUnauthorised(feeAdmin, paymaster.SIGNER_ADMIN_ROLE());
        paymaster.removeSigner(sponsor);
    }

    function test_feeAdministrationIsGated() public {
        _expectUnauthorised(feeCollector, paymaster.FEE_ADMIN_ROLE());
        paymaster.setDefaultFee(1);

        _expectUnauthorised(feeCollector, paymaster.FEE_ADMIN_ROLE());
        paymaster.setTenantFee(TENANT_A, true, 1);
    }

    /// @dev R-45. Deciding what tenants are charged and taking the proceeds are different powers.
    function test_theFeeAdminCannotCollectTheFeesItSets() public {
        _fund(TENANT_A, 1 ether);
        _expectUnauthorised(feeAdmin, paymaster.FEE_COLLECTOR_ROLE());
        paymaster.withdrawFees(feeAdmin, 1);
    }

    function test_theFeeCollectorCannotChangeTheRate() public {
        _expectUnauthorised(feeCollector, paymaster.FEE_ADMIN_ROLE());
        paymaster.setDefaultFee(0);
    }

    function test_stakeAdministrationIsGated() public {
        vm.deal(outsider, 1 ether);
        _expectUnauthorised(outsider, paymaster.STAKE_ADMIN_ROLE());
        paymaster.addStake{value: 0}(1 days);

        _expectUnauthorised(outsider, paymaster.STAKE_ADMIN_ROLE());
        paymaster.unlockStake();

        _expectUnauthorised(outsider, paymaster.STAKE_ADMIN_ROLE());
        paymaster.withdrawStake(payable(outsider));
    }

    function test_tenantAdministrationIsGated() public {
        _expectUnauthorised(outsider, paymaster.TENANT_ADMIN_ROLE());
        paymaster.registerTenant(bytes16(uint128(9)), outsider, 'x');

        _expectUnauthorised(outsider, paymaster.TENANT_ADMIN_ROLE());
        paymaster.setTenantWithdrawAddress(TENANT_A, outsider);

        _expectUnauthorised(outsider, paymaster.TENANT_ADMIN_ROLE());
        paymaster.setTenantEnabled(TENANT_A, false);
    }

    function test_parameterAdministrationIsGated() public {
        _expectUnauthorised(outsider, paymaster.PARAM_ADMIN_ROLE());
        paymaster.setPostOpGasAllowance(1);

        _expectUnauthorised(outsider, paymaster.PARAM_ADMIN_ROLE());
        paymaster.setPenaltyBps(1);
    }

    function test_pausingIsGated() public {
        _expectUnauthorised(outsider, paymaster.PAUSER_ROLE());
        paymaster.pause();

        vm.prank(pauser);
        paymaster.pause();

        _expectUnauthorised(outsider, paymaster.PAUSER_ROLE());
        paymaster.unpause();
    }

    // -----------------------------------------------------------------------------------------
    // No role reaches a tenant balance (R-48)
    // -----------------------------------------------------------------------------------------

    /// @dev The tenant-admin role can change where a tenant withdraws to. That is a real power and
    ///      worth naming: it cannot move funds itself, but it can point the exit somewhere else,
    ///      which is why it belongs behind the same timelocked grant as every other role.
    function test_noRoleCanWithdrawATenantsBalance() public {
        _fund(TENANT_A, 1 ether);
        address[9] memory holders = [roleAdmin, signerAdmin, feeAdmin, feeCollector, stakeAdmin, tenantAdmin, paramAdmin, pauser, upgrader];

        for (uint256 i = 0; i < holders.length; i++) {
            vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.NotWithdrawAddress.selector, TENANT_A, holders[i]));
            vm.prank(holders[i]);
            paymaster.withdrawTenant(TENANT_A, 1, holders[i]);
        }
    }

    /// @dev R-42's cap is what makes R-33 true: without it, the fee-withdrawal path reaches tenant
    ///      funds, because tenant balances and the treasury share one deposit.
    function test_theFeeCollectorCannotReachTenantFundsThroughTheTreasury() public {
        _fund(TENANT_A, 1 ether);
        assertEq(paymaster.treasury(), 0);

        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.ExceedsTreasury.selector, 1, 0));
        vm.prank(feeCollector);
        paymaster.withdrawFees(feeCollector, 1);
    }

    // -----------------------------------------------------------------------------------------
    // Auditability
    // -----------------------------------------------------------------------------------------

    /// @dev R-55's review is only cheap because the live role set is readable on-chain.
    function test_roleHoldersAreEnumerableOnChain() public view {
        assertEq(paymaster.getRoleMemberCount(paymaster.UPGRADER_ROLE()), 1);
        assertEq(paymaster.getRoleMember(paymaster.UPGRADER_ROLE(), 0), upgrader);
    }

    function test_theSignerSetIsReadableOnChain() public {
        assertEq(paymaster.signerCount(), 1);
        assertEq(paymaster.getSigners()[0], sponsor);

        address second = makeAddr('secondSigner');
        vm.prank(signerAdmin);
        paymaster.addSigner(second);
        assertEq(paymaster.signerCount(), 2);
        assertTrue(paymaster.isSigner(second));
    }

    function test_addingAnExistingSignerIsRejectedRatherThanSilentlyIgnored() public {
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.AlreadySigner.selector, sponsor));
        vm.prank(signerAdmin);
        paymaster.addSigner(sponsor);
    }

    function test_removingAnUnknownSignerIsRejected() public {
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.NotASigner.selector, outsider));
        vm.prank(signerAdmin);
        paymaster.removeSigner(outsider);
    }
}
