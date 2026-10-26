// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// The sponsorship paymaster's proxy is OpenZeppelin's stock ERC1967Proxy, deployed with an empty
// initialisation payload through CreateX's `deployCreate3AndInit`, which calls
// `GianoPaymaster.initialize` in the same transaction (deploy/cli.ts). Importing it here puts it in
// the build, and therefore in every release the deploy CLI deploys from.
import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';
