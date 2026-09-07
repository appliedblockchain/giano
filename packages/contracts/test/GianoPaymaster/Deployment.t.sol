// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {IAccessControl} from '@openzeppelin/contracts/access/IAccessControl.sol';
import {ERC1967Utils} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';
import {GianoPaymasterDeployer} from '../../src/paymaster/GianoPaymasterDeployer.sol';

contract DeploymentTest is PaymasterTestBase {
    function test_initialiseSetsTheConfigurationInStorageNotInBytecode() public view {
        assertEq(address(paymaster.entryPoint()), address(ENTRY_POINT));
        assertEq(paymaster.defaultFeeWei(), DEFAULT_FEE_WEI);
        assertEq(paymaster.postOpGasAllowance(), POST_OP_GAS_ALLOWANCE);
        assertEq(paymaster.penaltyBps(), PENALTY_BPS);
    }

    function test_theImplementationCannotBeInitialisedDirectly() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        implementation.initialize(address(ENTRY_POINT), roleAdmin, 0, 0, 0);
    }

    /// @dev O4's window. The deployer initialises in the same transaction as the CREATE2, so there
    ///      is no block in which an unconfigured proxy is sitting there to be claimed.
    function test_theProxyIsAlreadyInitialisedWhenTheDeployTransactionReturns() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vm.prank(outsider);
        paymaster.initialize(address(ENTRY_POINT), outsider, 0, 0, 0);
    }

    /// @dev Address stability (D10, R-49) rests on nothing operator-specific being in the init
    ///      code: the same salt and implementation must land on the same address for any operator.
    function test_theProxyAddressIsAPureFunctionOfSaltAndImplementation() public view {
        assertEq(deployer.predict(DEPLOY_SALT, address(implementation)), address(paymaster));
    }

    function test_twoOperatorsWithDifferentRoleAdminsGetTheSameAddress() public {
        GianoPaymasterDeployer other = new GianoPaymasterDeployer();
        GianoPaymaster otherImpl = new GianoPaymaster();

        address a = other.predict(DEPLOY_SALT, address(otherImpl));
        address deployed = other.deploy(
            DEPLOY_SALT,
            address(otherImpl),
            abi.encodeCall(GianoPaymaster.initialize, (address(ENTRY_POINT), outsider, 1, 2, 3))
        );
        assertEq(deployed, a, 'a different role admin must not move the address');
    }

    function test_deployRevertsIfInitialisationFails() public {
        GianoPaymasterDeployer other = new GianoPaymasterDeployer();
        vm.expectRevert();
        other.deploy(
            bytes32(uint256(1)),
            address(implementation),
            abi.encodeCall(GianoPaymaster.initialize, (address(0), roleAdmin, 0, 0, 0))
        );
    }

    function test_initialiseRejectsAZeroEntryPointOrRoleAdmin() public {
        GianoPaymaster impl = new GianoPaymaster();
        GianoPaymasterDeployer d = new GianoPaymasterDeployer();

        vm.expectRevert();
        d.deploy(bytes32(uint256(2)), address(impl), abi.encodeCall(GianoPaymaster.initialize, (address(ENTRY_POINT), address(0), 0, 0, 0)));
    }

    function test_initialiseRejectsAnAbsurdPenaltyRate() public {
        GianoPaymaster impl = new GianoPaymaster();
        GianoPaymasterDeployer d = new GianoPaymasterDeployer();

        vm.expectRevert();
        d.deploy(
            bytes32(uint256(3)),
            address(impl),
            abi.encodeCall(GianoPaymaster.initialize, (address(ENTRY_POINT), roleAdmin, 0, 0, 9999))
        );
    }

    function test_setPenaltyBpsRejectsAnAbsurdRate() public {
        vm.expectRevert(abi.encodeWithSelector(GianoPaymaster.PenaltyBpsTooHigh.selector, uint16(9999)));
        vm.prank(paramAdmin);
        paymaster.setPenaltyBps(9999);
    }

    // -----------------------------------------------------------------------------------------
    // Upgrades
    // -----------------------------------------------------------------------------------------

    function test_onlyTheUpgraderRoleCanReplaceTheImplementation() public {
        GianoPaymaster next = new GianoPaymaster();
        bytes32 role = paymaster.UPGRADER_ROLE();

        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, roleAdmin, role));
        vm.prank(roleAdmin);
        paymaster.upgradeToAndCall(address(next), '');
    }

    /// @dev R-52. Balances, treasury and every tenant field must survive an upgrade exactly; a
    ///      mis-ordered storage slot silently re-attributes real money.
    function test_anUpgradePreservesBalancesTreasuryAndTenantState() public {
        _fund(TENANT_A, 1 ether);
        _fund(TENANT_B, 2 ether);
        vm.prank(feeAdmin);
        paymaster.setTenantFee(TENANT_B, true, 42);

        // accrue something into the treasury
        vm.prank(address(ENTRY_POINT));
        paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            abi.encode(TENANT_A, uint128(0.001 ether), uint256(0), address(0), bytes32(0)),
            0,
            0
        );

        uint256 treasuryBefore = paymaster.treasury();
        uint128 balanceABefore = paymaster.getTenant(TENANT_A).balance;
        uint128 balanceBBefore = paymaster.getTenant(TENANT_B).balance;

        GianoPaymaster next = new GianoPaymaster();
        vm.prank(upgrader);
        paymaster.upgradeToAndCall(address(next), '');

        assertEq(address(uint160(uint256(vm.load(address(paymaster), ERC1967Utils.IMPLEMENTATION_SLOT)))), address(next));
        assertEq(paymaster.treasury(), treasuryBefore);
        assertEq(paymaster.getTenant(TENANT_A).balance, balanceABefore);
        assertEq(paymaster.getTenant(TENANT_B).balance, balanceBBefore);
        assertEq(paymaster.getTenant(TENANT_B).feeWeiOverride, 42);
        assertTrue(paymaster.getTenant(TENANT_B).hasFeeOverride);
        assertEq(paymaster.getTenant(TENANT_A).withdrawAddress, tenantAWithdraw);
        assertEq(paymaster.signerCount(), 1);
        assertEq(paymaster.getRoleMember(paymaster.ROLE_ADMIN(), 0), roleAdmin);
        _assertInvariant();
    }

    function test_aTenantCanStillWithdrawAfterAnUpgrade() public {
        _fund(TENANT_A, 1 ether);
        GianoPaymaster next = new GianoPaymaster();
        vm.prank(upgrader);
        paymaster.upgradeToAndCall(address(next), '');

        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 1 ether, tenantAWithdraw);
        assertEq(tenantAWithdraw.balance, 1 ether);
    }
}

