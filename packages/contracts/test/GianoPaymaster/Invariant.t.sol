// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from 'forge-std/Test.sol';
import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {IEntryPoint} from '@account-abstraction/contracts/interfaces/IEntryPoint.sol';

import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';
import {GianoPaymasterDeployer} from '../../src/paymaster/GianoPaymasterDeployer.sol';
import {Static} from '../GianoSmartWallet/Static.sol';

/// @dev Drives the paymaster through random sequences of everything that moves money.
///
///      Settlement is invoked directly as the EntryPoint would, which is what lets the sequence be
///      random. The deposit therefore only moves on funding and withdrawal — so what this suite
///      proves is that the *ledger arithmetic* can never come to claim more than the contract
///      holds, under any interleaving. That the overhead allowance also covers the EntryPoint's
///      own extra drawdown is the separate question `EndToEnd.t.sol` answers against a real
///      `handleOps`.
contract PaymasterHandler is Test {
    GianoPaymaster public paymaster;
    IEntryPoint public entryPoint;

    bytes16[] public tenantIds;
    mapping(bytes16 => address) public withdrawAddressOf;

    address public tenantAdmin;
    address public feeAdmin;
    address public feeCollector;
    address public paramAdmin;

    uint256 public totalFunded;
    uint256 public totalWithdrawn;

    constructor(
        GianoPaymaster paymaster_,
        IEntryPoint entryPoint_,
        bytes16[] memory tenantIds_,
        address[] memory withdrawAddresses_,
        address tenantAdmin_,
        address feeAdmin_,
        address feeCollector_,
        address paramAdmin_
    ) {
        paymaster = paymaster_;
        entryPoint = entryPoint_;
        tenantAdmin = tenantAdmin_;
        feeAdmin = feeAdmin_;
        feeCollector = feeCollector_;
        paramAdmin = paramAdmin_;
        for (uint256 i = 0; i < tenantIds_.length; i++) {
            tenantIds.push(tenantIds_[i]);
            withdrawAddressOf[tenantIds_[i]] = withdrawAddresses_[i];
        }
    }

    function _tenant(uint256 seed) internal view returns (bytes16) {
        return tenantIds[seed % tenantIds.length];
    }

    function fund(uint256 tenantSeed, uint256 amount) public {
        bytes16 id = _tenant(tenantSeed);
        amount = bound(amount, 1, 10 ether);
        vm.deal(address(this), amount);
        paymaster.depositFor{value: amount}(id);
        totalFunded += amount;
    }

    function settle(uint256 tenantSeed, uint256 gasCost, uint256 feeWei, uint256 gasLimit, uint256 feePerGas, bool ok) public {
        bytes16 id = _tenant(tenantSeed);
        gasCost = bound(gasCost, 0, 5 ether);
        feeWei = bound(feeWei, 0, 0.1 ether);
        gasLimit = bound(gasLimit, 0, 5_000_000);
        feePerGas = bound(feePerGas, 0, 500 gwei);

        vm.prank(address(entryPoint));
        paymaster.postOp(
            ok ? IPaymaster.PostOpMode.opSucceeded : IPaymaster.PostOpMode.opReverted,
            abi.encode(id, uint128(feeWei), gasLimit, address(this), bytes32(0)),
            gasCost,
            feePerGas
        );
    }

    function withdrawTenant(uint256 tenantSeed, uint256 amount) public {
        bytes16 id = _tenant(tenantSeed);
        uint256 balance = paymaster.getTenant(id).balance;
        if (balance == 0) return;
        amount = bound(amount, 1, balance);

        vm.prank(withdrawAddressOf[id]);
        paymaster.withdrawTenant(id, amount, withdrawAddressOf[id]);
        totalWithdrawn += amount;
    }

    function withdrawFees(uint256 amount) public {
        uint256 t = paymaster.treasury();
        if (t == 0) return;
        amount = bound(amount, 1, t);

        vm.prank(feeCollector);
        paymaster.withdrawFees(feeCollector, amount);
        totalWithdrawn += amount;
    }

    function changeFee(uint256 amount) public {
        vm.prank(feeAdmin);
        paymaster.setDefaultFee(uint128(bound(amount, 0, 1 ether)));
    }

    function changeParams(uint256 gasUnits, uint256 bps) public {
        vm.startPrank(paramAdmin);
        paymaster.setPostOpGasAllowance(uint32(bound(gasUnits, 0, 500_000)));
        paymaster.setPenaltyBps(uint16(bound(bps, 0, 5000)));
        vm.stopPrank();
    }

    function toggleTenant(uint256 tenantSeed, bool enabled) public {
        vm.prank(tenantAdmin);
        paymaster.setTenantEnabled(_tenant(tenantSeed), enabled);
    }

    function tenantCount() external view returns (uint256) {
        return tenantIds.length;
    }

    receive() external payable {}
}

contract InvariantTest is Test {
    IEntryPoint internal constant ENTRY_POINT = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);

    GianoPaymaster internal paymaster;
    PaymasterHandler internal handler;
    bytes16[] internal tenantIds;

    address internal roleAdmin = makeAddr('roleAdmin');
    address internal tenantAdmin = makeAddr('tenantAdmin');
    address internal feeAdmin = makeAddr('feeAdmin');
    address internal feeCollector = makeAddr('feeCollector');
    address internal paramAdmin = makeAddr('paramAdmin');

    function setUp() public {
        vm.etch(address(ENTRY_POINT), Static.ENTRY_POINT_BYTES);

        GianoPaymaster impl = new GianoPaymaster();
        GianoPaymasterDeployer deployer = new GianoPaymasterDeployer();
        paymaster = GianoPaymaster(
            payable(
                deployer.deploy(
                    bytes32(uint256(7)),
                    address(impl),
                    abi.encodeCall(GianoPaymaster.initialize, (address(ENTRY_POINT), roleAdmin, 0.0001 ether, 40_000, 1000))
                )
            )
        );

        vm.startPrank(roleAdmin);
        paymaster.grantRole(paymaster.TENANT_ADMIN_ROLE(), tenantAdmin);
        paymaster.grantRole(paymaster.FEE_ADMIN_ROLE(), feeAdmin);
        paymaster.grantRole(paymaster.FEE_COLLECTOR_ROLE(), feeCollector);
        paymaster.grantRole(paymaster.PARAM_ADMIN_ROLE(), paramAdmin);
        vm.stopPrank();

        address[] memory withdrawAddresses = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            bytes16 id = bytes16(uint128(i + 1));
            address w = makeAddr(string.concat('withdraw', vm.toString(i)));
            tenantIds.push(id);
            withdrawAddresses[i] = w;
            vm.prank(tenantAdmin);
            paymaster.registerTenant(id, w, 'tenant');
        }

        handler = new PaymasterHandler(
            paymaster,
            ENTRY_POINT,
            tenantIds,
            withdrawAddresses,
            tenantAdmin,
            feeAdmin,
            feeCollector,
            paramAdmin
        );

        targetContract(address(handler));
    }

    /// @dev The property the whole design rests on. A breach is an insolvency: the ledger would be
    ///      promising money the deposit does not hold, and one tenant's claim would be payable
    ///      only out of another's funds.
    function invariant_claimsNeverExceedTheDeposit() public view {
        uint256 claims = paymaster.treasury();
        for (uint256 i = 0; i < tenantIds.length; i++) {
            claims += paymaster.getTenant(tenantIds[i]).balance;
        }
        assertLe(claims, ENTRY_POINT.balanceOf(address(paymaster)));
    }

    /// @dev A deficit is money the pooled deposit already absorbed on a tenant's behalf. It must
    ///      never coexist with a balance for that tenant: if there were funds left, the settlement
    ///      would have taken them instead of recording a shortfall.
    function invariant_aTenantNeverHoldsABalanceAndADeficitAtOnce() public view {
        for (uint256 i = 0; i < tenantIds.length; i++) {
            GianoPaymaster.Tenant memory t = paymaster.getTenant(tenantIds[i]);
            if (t.deficit > 0) assertEq(t.balance, 0);
        }
    }

    /// @dev The treasury can only ever have been credited out of a tenant balance, so it can never
    ///      exceed everything that was ever paid in.
    function invariant_theTreasuryCannotExceedWhatWasEverFunded() public view {
        assertLe(paymaster.treasury(), handler.totalFunded());
    }
}
