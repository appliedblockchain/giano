// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {IAccessControl} from '@openzeppelin/contracts/access/IAccessControl.sol';
import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';
import {ERC1967Utils} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {ICreateX} from '../utils/CreateXFixture.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';

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

    /// @dev O4's window. CreateX initialises in the same transaction as the CREATE3, so there is
    ///      no block in which an unconfigured proxy is sitting there to be claimed.
    function test_theProxyIsAlreadyInitialisedWhenTheDeployTransactionReturns() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        vm.prank(outsider);
        paymaster.initialize(address(ENTRY_POINT), outsider, 0, 0, 0);
    }

    /// @dev The proxy address is a pure function of the deployer and the label: no bytecode and no
    ///      configuration enters it (deploy/create3.ts).
    function test_theProxyAddressIsAPureFunctionOfDeployerAndLabel() public view {
        assertEq(_create3Address(canonicalDeployer, PROXY_LABEL), address(paymaster));
    }

    function test_neitherTheConfigurationNorTheImplementationMovesTheAddress() public {
        uint256 snapshot = vm.snapshotState();
        address first = _deployPaymasterProxy(
            canonicalDeployer,
            'giano.paymaster.proxy.config-test',
            address(implementation),
            abi.encodeCall(
                GianoPaymaster.initialize,
                (address(ENTRY_POINT), roleAdmin, DEFAULT_FEE_WEI, POST_OP_GAS_ALLOWANCE, PENALTY_BPS)
            )
        );
        vm.revertToState(snapshot);

        address second = _deployPaymasterProxy(
            canonicalDeployer,
            'giano.paymaster.proxy.config-test',
            address(new GianoPaymaster()),
            abi.encodeCall(GianoPaymaster.initialize, (address(ENTRY_POINT), outsider, 1, 2, 3))
        );
        assertEq(second, first, 'a different implementation or role admin must not move the address');
    }

    /// @dev The salt is permissioned: CreateX treats it as an ordinary salt when anyone but the
    ///      deployer sends it, so nobody else can occupy a canonical address on a chain we have not
    ///      adopted yet.
    function test_onlyTheCanonicalDeployerCanUseItsSalts() public {
        string memory label = 'giano.paymaster.proxy.squat-test';
        address canonical = _create3Address(canonicalDeployer, label);

        vm.prank(outsider);
        address squatted = CREATEX.deployCreate3AndInit(
            _create3Salt(canonicalDeployer, label),
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(address(implementation), '')),
            abi.encodeCall(GianoPaymaster.initialize, (address(ENTRY_POINT), outsider, 0, 0, 0)),
            ICreateX.Values(0, 0)
        );
        assertTrue(squatted != canonical, 'an outsider landed on the canonical address');
        assertEq(canonical.code.length, 0);
    }

    function test_deployRevertsIfInitialisationFails() public {
        vm.expectRevert();
        _deployPaymasterProxy(
            canonicalDeployer,
            'giano.paymaster.proxy.fail-1',
            address(implementation),
            abi.encodeCall(GianoPaymaster.initialize, (address(0), roleAdmin, 0, 0, 0))
        );
    }

    function test_initialiseRejectsAZeroEntryPointOrRoleAdmin() public {
        vm.expectRevert();
        _deployPaymasterProxy(
            canonicalDeployer,
            'giano.paymaster.proxy.fail-2',
            address(implementation),
            abi.encodeCall(GianoPaymaster.initialize, (address(ENTRY_POINT), address(0), 0, 0, 0))
        );
    }

    function test_initialiseRejectsAnAbsurdPenaltyRate() public {
        vm.expectRevert();
        _deployPaymasterProxy(
            canonicalDeployer,
            'giano.paymaster.proxy.fail-3',
            address(implementation),
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

