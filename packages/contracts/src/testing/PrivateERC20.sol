// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';

contract PrivateERC20 is ERC20 {
    error Unauthorized(address expectedSender, address actualSender);

    constructor(uint256 initialSupply) ERC20('Private ERC20', 'PE2') {
        _mint(msg.sender, initialSupply);
    }

	function mint(uint256 amount) public {
		_mint(msg.sender, amount);
	}

    function privateBalanceOf(address account) public view returns (uint256) {
        require(account == msg.sender, Unauthorized(account, msg.sender));
        return super.balanceOf(account);
    }
}
