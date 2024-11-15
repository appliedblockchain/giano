// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Account} from './Account.sol';
import {AbstractAccountFactory} from './AbstractAccountFactory.sol';
import {Types} from './Types.sol';

contract AccountFactory is AbstractAccountFactory {
    function deployContract(Types.PublicKey memory publicKey) internal virtual override returns (address) {
        return address(new Account(publicKey));
    }
}
