// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

interface IBeaconBlockHashReceiver {
    struct BeaconBlockHashRecord {
        uint256 slot;
        bytes32 blockHash;
    }

    function setBeaconBlockHash(BeaconBlockHashRecord calldata blockRecord) external;
    function setBeaconBlockHashes(BeaconBlockHashRecord[] calldata blockRecords) external;
}