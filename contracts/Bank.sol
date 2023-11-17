// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./Base64.sol";
import "./Secp256r1.sol";

contract Bank {
  address public owner;
  address[] public holders;
  uint256 public holdersCount;
  mapping(address => uint256) public holderToAmount;
  //
  mapping(bytes32 => PassKeyId) private authorisedKeys;
  bytes32[] private knownKeyHashes;

  event Registration(address indexed holder);
  event Deposit(address indexed holder, string signature, address authorizedAddress, uint256 amount);

  modifier onlyOwner() {
    require(msg.sender == owner, "Only the owner can access this function.");
    _;
  }

  constructor() {
    owner = msg.sender;
  }

  function register() public returns (bool) {
    // check if not already registered!
    holders.push(msg.sender);
    holdersCount++;
    holderToAmount[msg.sender] = 0;
    emit Registration(msg.sender);
    return true;
  }

  function deposit(string memory signature, address authorizedAddress, uint256 amount) public returns (bool) {
    holderToAmount[msg.sender] += amount;
    emit Deposit(msg.sender, signature, authorizedAddress, amount);
    return true;
  }

  function getBalance(address holder) public view returns (uint256) {
    return holderToAmount[holder];
  }

  // ref: https://github.com/itsobvioustech/aa-passkeys-wallet/blob/main/src/PassKeysAccount.sol#L84
  function validateSignature(string calldata signature, bytes32 userOpHash) internal override virtual returns (uint256 validationData) {
    (bytes32 keyHash, uint256 sigx, uint256 sigy, bytes memory authenticatorData, string memory clientDataJSONPre, string memory clientDataJSONPost) =
              abi.decode(signature, (bytes32, uint256, uint256, bytes, string, string));

    string memory opHashBase64 = Base64.encode(bytes.concat(userOpHash));
    string memory clientDataJSON = string.concat(clientDataJSONPre, opHashBase64, clientDataJSONPost);
    bytes32 clientHash = sha256(bytes(clientDataJSON));
    bytes32 sigHash = sha256(bytes.concat(authenticatorData, clientHash));

    PassKeyId memory passKey = authorisedKeys[keyHash];
    require(Secp256r1.Verify(passKey, sigx, sigy, uint256(sigHash)), "Invalid signature");
    return 0;
  }
}
