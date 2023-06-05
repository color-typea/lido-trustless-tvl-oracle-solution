// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

interface IBeaconBlockHashProvider {
    function getBeaconBlockHash(uint256 slot) external view returns (bytes32);
}