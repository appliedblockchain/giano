// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';

/// @dev Exists only so `forge inspect` can report the paymaster's storage layout.
///
///      `GianoPaymaster` keeps all of its state in an ERC-7201 namespace addressed from assembly,
///      which is what makes appending fields safe and what stops any future contract colliding with
///      it — but it also means the compiler reports *no* storage layout for the contract at all.
///      Declaring the same struct as an ordinary state variable here recovers the layout that
///      matters, so `scripts/storage-layout.mjs` has something to snapshot.
///
///      Deliberately under `test/`, so it is never compiled into the published artifacts and can
///      never be deployed.
contract PaymasterStorageProbe {
    GianoPaymaster.PaymasterStorage internal paymasterStorage;

    /// @dev Keeps the variable from being optimised away and the file from warning about it.
    function treasury() external view returns (uint256) {
        return paymasterStorage.treasury;
    }
}
