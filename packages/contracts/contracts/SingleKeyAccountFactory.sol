// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';
import {SingleKeyAccount} from './SingleKeyAccount.sol';
import {Create2} from '@openzeppelin/contracts/utils/Create2.sol';

contract SingleKeyAccountFactory {
    struct User {
        uint256 id;
        Types.PublicKey publicKey;
        address account;
    }

    mapping(uint256 => User) private _users;
    bytes32 private immutable _factorySalt;

    event UserCreated(uint256 userId, Types.PublicKey publicKey, address account);
    error UserAlreadyExists(uint256 id);

    constructor(bytes32 factorySalt) {
        _factorySalt = factorySalt;
    }

    function getUser(uint256 id) public view returns (User memory) {
        return _users[id];
    }

    function createUser(uint256 id, Types.PublicKey memory publicKey) public {
        if (_users[id].account != address(0)) {
            revert UserAlreadyExists(id);
        }
        address account = _deployContract(publicKey);
        _users[id] = User(id, publicKey, account);

        emit UserCreated(id, publicKey, account);
    }

    function _deployContract(Types.PublicKey memory publicKey) internal returns (address) {
        bytes32 salt = keccak256(abi.encode(_factorySalt, publicKey.x, publicKey.y));
        bytes memory bytecode = abi.encodePacked(
            type(SingleKeyAccount).creationCode,
            abi.encode(publicKey)
        );
        
        return Create2.deploy(0, salt, bytecode);
    }

    function getAccountAddress(Types.PublicKey memory publicKey) public view returns (address) {
        bytes32 salt = keccak256(abi.encode(_factorySalt, publicKey.x, publicKey.y));
        bytes memory bytecode = abi.encodePacked(
            type(SingleKeyAccount).creationCode,
            abi.encode(publicKey)
        );
        
        return Create2.computeAddress(salt, keccak256(bytecode));
    }
}
