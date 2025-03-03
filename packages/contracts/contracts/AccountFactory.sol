// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Account} from './Account.sol';
import {AbstractAccountFactory} from './AbstractAccountFactory.sol';
import {Types} from './Types.sol';

contract AccountFactory is AbstractAccountFactory {
    function deployAccount(Types.PublicKey calldata publicKey, address registry) external override returns (address) {
        return address(new Account(publicKey, registry));
    }
}
