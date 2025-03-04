// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Account} from './Account.sol';
import {AbstractAccountFactory} from './AbstractAccountFactory.sol';
import {Types} from './Types.sol';

/**
 * @title AccountFactory
 * @author Giano Team
 * @notice Factory contract for deploying new Account contracts
 * @dev This is a concrete implementation of the AbstractAccountFactory that
 * creates new Account contracts using the 'new' keyword.
 */
contract AccountFactory is AbstractAccountFactory {
    /**
     * @notice Deploys a new Account contract with the given public key and registry address
     * @dev Creates a new Account instance and returns its address
     * @param publicKey The public key to associate with the account as the admin key
     * @param registry The address of the registry contract that will manage the account
     * @return The address of the deployed Account contract
     */
    function deployAccount(Types.PublicKey calldata publicKey, address registry) external override returns (address) {
        return address(new Account(publicKey, registry));
    }
}
