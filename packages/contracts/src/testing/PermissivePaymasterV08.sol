// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {PackedUserOperation as PackedUserOperationV08} from 'account-abstraction-v08/interfaces/PackedUserOperation.sol';
import {BasePaymaster as BasePaymasterV08} from 'account-abstraction-v08/core/BasePaymaster.sol';
import {IEntryPoint as IEntryPointV08} from 'account-abstraction-v08/interfaces/IEntryPoint.sol';

error OnlyEntrypoint();

contract PermissivePaymasterV08 is BasePaymasterV08 {

    constructor(address _entryPoint) BasePaymasterV08(IEntryPointV08(_entryPoint)) {
        entryPoint = IEntryPointV08(_entryPoint);
    }

    function _validatePaymasterUserOp(
        PackedUserOperationV08 calldata,
        bytes32 /* userOpHash */,
        uint256 /* maxCost */
    ) internal view override returns (bytes memory context, uint256 validationData) {
        if (msg.sender != address(entryPoint)) {
            revert OnlyEntrypoint();
        }
        // Always approve: return empty context and 0 validationData (valid forever)
        return ('', 0);
    }

    function _postOp(BasePaymasterV08.PostOpMode, bytes calldata, uint256, uint256) internal view override {
        if (msg.sender != address(entryPoint)) {
            revert OnlyEntrypoint();
        }
    }

    // deposit any amounts it receives to the EntryPoint
    receive() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }
}
