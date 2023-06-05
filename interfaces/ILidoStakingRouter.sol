// SPDX-License-Identifier: Apache-2.0.

pragma solidity ^0.8.0;

// Lido staiking router
// https://github.com/lidofinance/lido-dao/blob/master/contracts/0.8.9/StakingRouter.sol
// This is a "partial" interface, only including functions we use
interface ILidoStakingRouter {
    function getWithdrawalCredentials() external view returns (bytes32);
}