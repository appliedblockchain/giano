// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';

/**
 * @title AbstractAccountFactory
 * @author Giano Team
 * @notice Base contract for deploying account contracts
 * @dev This abstract contract defines the interface that concrete factory
 * implementations must conform to for deploying Account contracts.
 */
abstract contract AbstractAccountFactory {
    /**
     * @notice Deploys a new Account contract
     * @dev Must be implemented by derived contracts
     * @param credentialId The credential identifier for the admin credential
     * @param publicKey The public key for the admin credential
     * @param registry The address of the AccountRegistry contract
     * @return The address of the deployed Account contract
     */
    function deployAccount(bytes calldata credentialId, Types.PublicKey calldata publicKey, address registry) public virtual returns (address);
}
