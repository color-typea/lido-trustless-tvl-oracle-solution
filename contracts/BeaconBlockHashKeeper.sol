// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

import "../interfaces/IBeaconBlockHashProvider.sol";
import "../interfaces/IBeaconBlockHashReceiver.sol";


contract BeaconBlockHashKeeper is IBeaconBlockHashProvider, IBeaconBlockHashReceiver {
    mapping(uint256=>bytes32) blockHashes;

    function getBeaconBlockHash(uint256 slot) external view returns (bytes32) {
        bytes32 value = blockHashes[slot];
        require(value != 0); // means that the hash was not set, ever
        return (value);
    }

    function setBeaconBlockHash(BeaconBlockHashRecord calldata blockRecord) external {
        blockHashes[blockRecord.slot] = blockRecord.blockHash;
    }

    function setBeaconBlockHashes(BeaconBlockHashRecord[] calldata blockRecords) external {
        for (uint32 i = 0; i < blockRecords.length; i++) {
            this.setBeaconBlockHash(blockRecords[i]);
        }
    }
}