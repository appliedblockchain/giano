// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console2} from 'forge-std/Test.sol';
import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {PackedUserOperation} from '@account-abstraction/contracts/interfaces/PackedUserOperation.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';

/// @dev Budgets from §3.8 of the specification. These are ceilings, not targets: `postOp` running
///      out of gas is a `PostOpReverted` for the whole operation, so a regression that pushes
///      settlement past the recommended `paymasterPostOpGasLimit` has to fail CI rather than be
///      discovered in production.
contract GasTest is PaymasterTestBase {
    address internal wallet = makeAddr('wallet');

    uint256 internal constant VALIDATION_BUDGET = 60_000;
    uint256 internal constant SETTLEMENT_BUDGET = 80_000;

    function setUp() public override {
        super.setUp();
        _fund(TENANT_A, 1 ether);
    }

    function test_gas_validation() public {
        PackedUserOperation memory op = _sponsoredOp(
            _defaultOpParams(wallet),
            TENANT_A,
            uint48(block.timestamp + 120),
            0,
            DEFAULT_FEE_WEI
        );

        vm.prank(address(ENTRY_POINT));
        uint256 before = gasleft();
        paymaster.validatePaymasterUserOp(op, keccak256('h'), 0.001 ether);
        uint256 used = before - gasleft();

        console2.log('validatePaymasterUserOp gas', used);
        assertLt(used, VALIDATION_BUDGET, 'validation gas regressed past its budget');
    }

    function test_gas_settlement() public {
        bytes memory ctx = abi.encode(TENANT_A, DEFAULT_FEE_WEI, uint256(300_000), wallet, keccak256('h'), uint256(0));

        vm.prank(address(ENTRY_POINT));
        uint256 before = gasleft();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 0.001 ether, 1 gwei);
        uint256 used = before - gasleft();

        console2.log('postOp gas (cold treasury)', used);
        assertLt(used, SETTLEMENT_BUDGET, 'settlement gas regressed past its budget');
    }

    /// @dev The most expensive settlement: cold slots, a fee only partly covered, so the treasury
    ///      goes from zero to non-zero and a deficit is opened, with all three events. It must fit
    ///      under `MIN_POST_OP_GAS_LIMIT`, or a client at the floor could still make `postOp` run
    ///      out of gas and leave the tenant uncharged.
    function test_gas_settlementWorstCaseFitsUnderThePostOpFloor() public {
        uint256 executionGasLimit = 300_000;
        uint256 actualGasCost = 0.001 ether;
        uint256 owed = actualGasCost + _overheadWei(1 gwei, executionGasLimit);
        _fund(TENANT_B, owed + DEFAULT_FEE_WEI / 2);
        bytes memory ctx = abi.encode(TENANT_B, DEFAULT_FEE_WEI, executionGasLimit, wallet, keccak256('h'), uint256(0));

        vm.prank(address(ENTRY_POINT));
        uint256 before = gasleft();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, actualGasCost, 1 gwei);
        uint256 used = before - gasleft();

        assertGt(paymaster.getTenant(TENANT_B).deficit, 0, 'the scenario must open a deficit');
        assertGt(paymaster.treasury(), 0, 'the scenario must credit an empty treasury');
        console2.log('postOp gas (worst case)', used);
        assertLt(used, paymaster.MIN_POST_OP_GAS_LIMIT(), 'settlement no longer fits under the postOp floor');
    }

    /// @dev The steady-state cost, once the treasury slot is warm — this is what most operations
    ///      actually pay, and what `postOpGasAllowance` should be calibrated against.
    function test_gas_settlementWarm() public {
        bytes memory ctx = abi.encode(TENANT_A, DEFAULT_FEE_WEI, uint256(300_000), wallet, keccak256('h'), uint256(0));
        vm.prank(address(ENTRY_POINT));
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 0.001 ether, 1 gwei);

        vm.prank(address(ENTRY_POINT));
        uint256 before = gasleft();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 0.001 ether, 1 gwei);
        uint256 used = before - gasleft();

        console2.log('postOp gas (warm)', used);
        assertLt(used, SETTLEMENT_BUDGET);
    }
}
