// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';

/**
 * @title AbstractAccountFactory
 * @dev Base contract for deploying account contracts
 */
abstract contract AbstractAccountFactory {
    /**
     * @dev Deploy an account contract with the given public key and registry address
     * @param publicKey The public key to associate with the account
     * @param registry The address of the registry contract
     * @return The address of the deployed account
     */
    function deployAccount(Types.PublicKey calldata publicKey, address registry) external virtual returns (address);
}
