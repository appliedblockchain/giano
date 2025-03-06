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
     * @param publicKeyX The X coordinate of the initial admin key
     * @param publicKeyY The Y coordinate of the initial admin key
     * @param registry The address of the registry
     */
    event AccountDeployed(address indexed account, bytes32 indexed publicKeyX, bytes32 publicKeyY, address indexed registry);

    /**
     * @notice Deploys a new Account contract with the given public key and registry address
     * @dev Creates a new Account instance using CREATE2 for predictable addresses and returns its address
     * @param publicKey The public key to associate with the account as the admin key
     * @param registry The address of the registry contract that will manage the account
     * @return accountAddress The address of the deployed Account contract
     */
    function deployAccount(Types.PublicKey calldata publicKey, address registry) external override returns (address accountAddress) {
        // Compute salt from public key and registry
        bytes32 salt = keccak256(abi.encode(publicKey.x, publicKey.y, registry));
        
        // Deploy using CREATE2 for deterministic addresses
        accountAddress = address(new Account{salt: salt}(publicKey, registry));
        
        emit AccountDeployed(accountAddress, publicKey.x, publicKey.y, registry);
        
        return accountAddress;
    }

    /**
     * @notice Computes the address where an account would be deployed
     * @dev Uses the same logic as deployAccount to predict the address without deploying
     * @param publicKey The public key that would be associated with the account
     * @param registry The address of the registry that would manage the account
     * @return The predicted address where the account would be deployed
     */
    function computeAccountAddress(Types.PublicKey calldata publicKey, address registry) external view returns (address) {
        bytes32 salt = keccak256(abi.encode(publicKey.x, publicKey.y, registry));
        
        // Compute the CREATE2 address
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(abi.encodePacked(
                type(Account).creationCode,
                abi.encode(publicKey, registry)
            ))
        )))));
    }
}
