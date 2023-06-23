// SPDX-FileCopyrightText: 2023 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

import { UnstructuredStorage } from '../lido/0.8.9/lib/UnstructuredStorage.sol';
import { BeaconBlockHashKeeperOracle } from '../BeaconBlockHashKeeperOracle.sol';

interface ITimeProvider {
    function getTime() external view returns (uint256);
}

contract BeaconBlockHashKeeperOracleTimeTravellable is BeaconBlockHashKeeperOracle, ITimeProvider {
    using UnstructuredStorage for bytes32;

    constructor(
        uint256 secondsPerSlot,
        uint256 genesisTime
    ) BeaconBlockHashKeeperOracle(secondsPerSlot, genesisTime) {
        // allow usage without a proxy for tests
        CONTRACT_VERSION_POSITION.setStorageUint256(0);
    }

    function getTime() external view returns (uint256) {
        return _getTime();
    }

    function _getTime() internal view override returns (uint256) {
        address consensus = CONSENSUS_CONTRACT_POSITION.getStorageAddress();
        return ITimeProvider(consensus).getTime();
    }
}
