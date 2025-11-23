// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';
import '@openzeppelin/contracts/interfaces/IERC1271.sol';

contract PrivateERC20 is ERC20 {
    error Unauthorized(address expectedSender, address actualSender);
    error InvalidMessageType();
    error InvalidSignature();

    // EIP-712 type hash for Message
    bytes32 public constant MESSAGE_TYPEHASH = keccak256("Message(string content,uint256 timestamp)");
    
    // Domain separator for EIP-712
    bytes32 public DOMAIN_SEPARATOR;

    constructor(uint256 initialSupply) ERC20('Private ERC20', 'PE2') {
        _mint(msg.sender, initialSupply);
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("PrivateERC20")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

	function mint(uint256 amount) public {
		_mint(msg.sender, amount);
	}

    function privateBalanceOf(address account) public view returns (uint256) {
        require(account == msg.sender, Unauthorized(account, msg.sender));
        return super.balanceOf(account);
    }

    /// @notice Demonstrates EIP-712 typed data signing and validation in a smart contract
    /// @dev This method shows how to:
    ///      1. Create EIP-712 compliant message hashes
    ///      2. Validate signatures using ERC1271 standard
    ///      3. Integrate with GianoSmartWallet for signature verification
    /// @param content The message content to be validated
    /// @param timestamp The message timestamp for replay protection
    /// @param signature The EIP-712 signature from the approver
    /// @param approver The address of the GianoSmartWallet that signed the message
    /// @return bool True if the signature is valid, false otherwise
    function approveMessage(
        string memory content,
        uint256 timestamp,
        bytes calldata signature,
        address approver
    ) public view returns (bool) {
        // Create the message hash
        bytes32 messageHash = keccak256(abi.encode(MESSAGE_TYPEHASH, keccak256(bytes(content)), timestamp));
        
        // Create the EIP-712 hash
        bytes32 eip712Hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, messageHash));
        
        // Verify the signature using the ERC1271 interface
        try IERC1271(approver).isValidSignature(eip712Hash, signature) returns (bytes4 result) {
            // Check if the signature is valid (0x1626ba7e is the magic value for valid signatures)
            // ... or if the signature is valid, do some contract actions ...
            return result == 0x1626ba7e;
        } catch {
            revert InvalidSignature();
        }
    }

    /// @notice Gets the domain separator for EIP-712 signing
    function getDomainSeparator() public view returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }

    /// @notice Gets the message type hash for EIP-712 signing
    function getMessageTypeHash() public pure returns (bytes32) {
        return MESSAGE_TYPEHASH;
    }
}
