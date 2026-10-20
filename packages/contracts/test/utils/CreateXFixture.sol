// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from 'forge-std/Test.sol';
import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';

/// @dev The slice of CreateX (github.com/pcaversaccio/createx) the deploy CLI uses.
interface ICreateX {
    struct Values {
        uint256 constructorAmount;
        uint256 initCallAmount;
    }

    function deployCreate3(bytes32 salt, bytes memory initCode) external payable returns (address newContract);

    function deployCreate3AndInit(
        bytes32 salt,
        bytes memory initCode,
        bytes memory data,
        Values memory values
    ) external payable returns (address newContract);

    function computeCreate3Address(bytes32 salt) external view returns (address computedAddress);
}

/// @dev Deploys the way production does: CreateX at its canonical address, CREATE3, permissioned
///      salts (`deploy/create3.ts`). The vendored artifact is the same build every chain carries.
abstract contract CreateXFixture is Test {
    ICreateX internal constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function _installCreateX() internal {
        if (address(CREATEX).code.length == 0) deployCodeTo('vendor/createx/CreateX.json', address(CREATEX));
    }

    /// @dev `deployer ‖ 0x00 ‖ keccak256(label)[0:11]`, as `create3Salt` in deploy/create3.ts.
    function _create3Salt(address deployer, string memory label) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(deployer, bytes1(0x00), bytes11(keccak256(bytes(label)))));
    }

    /// @dev The address CreateX gives `label` for `deployer` (its permissioned guard, then CREATE3).
    function _create3Address(address deployer, string memory label) internal view returns (address) {
        bytes32 guarded = keccak256(abi.encodePacked(bytes32(uint256(uint160(deployer))), _create3Salt(deployer, label)));
        return CREATEX.computeCreate3Address(guarded);
    }

    /// @dev The paymaster's deployment: a stock ERC1967Proxy with an empty payload, initialised by
    ///      CreateX in the same transaction.
    function _deployPaymasterProxy(
        address deployer,
        string memory label,
        address implementation,
        bytes memory initCalldata
    ) internal returns (address) {
        vm.prank(deployer);
        return CREATEX.deployCreate3AndInit(
            _create3Salt(deployer, label),
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, '')),
            initCalldata,
            ICreateX.Values(0, 0)
        );
    }
}
