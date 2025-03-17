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
 * creates new Account contracts using CREATE2 opcode for address predictability.
 */
contract AccountFactory is AbstractAccountFactory {
    /**
     * @notice Emitted when a new account is deployed
     * @param account The address of the deployed account
     * @param credentialId The key identifier for the admin key
     */
    event AccountDeployed(address indexed account, bytes credentialId);

    /**
     * @notice Deploys a new Account contract with the given public key and registry address
     * @dev Creates a new Account instance using CREATE2 for predictable addresses and returns its address
     * @param credentialId The key identifier for the admin key
     * @param publicKey The public key to associate with the account as the admin key
     * @param registry The address of the registry contract that will manage the account
     * @return accountAddress The address of the deployed Account contract
     */
    function deployAccount(bytes calldata credentialId, Types.PublicKey calldata publicKey, address registry) public override returns (address accountAddress) {
        // Compute the salt using all parameters to ensure deterministic addresses
        bytes32 salt = keccak256(abi.encode(publicKey, credentialId, registry));
        
        // Deploy the account contract
        accountAddress = address(new Account{salt: salt}(publicKey, credentialId, registry));
        
        emit AccountDeployed(accountAddress, credentialId);
        
        return accountAddress;
    }

    /**
     * @notice Computes the address where an account would be deployed
     * @dev Uses the same logic as deployAccount to predict the address without deploying
     * @param credentialId The key identifier for the admin key
     * @param publicKey The public key that would be associated with the account
     * @param registry The address of the registry that would manage the account
     * @return The predicted address where the account would be deployed
     */
    function computeAccountAddress(bytes calldata credentialId, Types.PublicKey calldata publicKey, address registry) public view returns (address) {
        // Compute the salt using all parameters to ensure deterministic addresses
        bytes32 salt = keccak256(abi.encode(publicKey, credentialId, registry));
        
        // Compute the address using CREATE2
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(abi.encodePacked(type(Account).creationCode, abi.encode(publicKey, credentialId, registry)))
        )))));
    }
}
