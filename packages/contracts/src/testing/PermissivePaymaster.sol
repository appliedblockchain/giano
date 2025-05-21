// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {PackedUserOperation} from '@account-abstraction/contracts/interfaces/PackedUserOperation.sol';
import {BasePaymaster} from '@account-abstraction/contracts/core/BasePaymaster.sol';
import {IEntryPoint} from '@account-abstraction/contracts/interfaces/IEntryPoint.sol';

error OnlyEntrpoint();

contract PermissivePaymaster is BasePaymaster {
    constructor(address _entryPoint) BasePaymaster(IEntryPoint(_entryPoint)) {}

    function _validatePaymasterUserOp(
        PackedUserOperation calldata,
        bytes32 /* userOpHash */,
        uint256 /* maxCost */
    ) internal pure override returns (bytes memory context, uint256 validationData) {
        // Always approve: return empty context and 0 validationData (valid forever)
        return ('', 0);
    }

    function _postOp(BasePaymaster.PostOpMode, bytes calldata, uint256, uint256) internal override {}

    // deposit any amounts it receives to the EntryPoint
    receive() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }
}
