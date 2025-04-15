// SPDX-License-Identifier: MIT

pragma solidity ^0.8.27;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';

contract PrivateERC20 is ERC20 {
    error Unauthorized();

    constructor() ERC20('PrivateToken', 'PTK') {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function balanceOf(address owner) public view override returns (uint256) {
        require(msg.sender == owner, Unauthorized());
        return super.balanceOf(owner);
    }
}
