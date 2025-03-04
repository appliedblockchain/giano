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
     * @notice Deploys an account contract with the given public key and registry address
     * @dev This function must be implemented by concrete factory contracts
     * @param publicKey The public key to associate with the account as the admin key
     * @param registry The address of the registry contract that will manage the account
     * @return The address of the deployed account contract
     */
    function deployAccount(Types.PublicKey calldata publicKey, address registry) external virtual returns (address);
}
