// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AbstractAccountFactory} from './AbstractAccountFactory.sol';
import {ERC721SafeTransferAccount} from './ERC721SafeTransferAccount.sol';
import {Types} from './Types.sol';

contract ERC721SafeTransferAccountFactory is AbstractAccountFactory {
    function deployContract(Types.PublicKey memory publicKey) internal virtual override returns (address) {
        return address(new ERC721SafeTransferAccount(publicKey));
    }
}
