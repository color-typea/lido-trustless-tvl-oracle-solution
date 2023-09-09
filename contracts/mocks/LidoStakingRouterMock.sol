// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8 <0.9;

import "../../interfaces/ILidoStakingRouter.sol";


contract LidoStakingRouterMock is ILidoStakingRouter {
    bytes32 withdrawalCredentials;
    constructor(bytes32 withdrawalCredentials_) {
        withdrawalCredentials = withdrawalCredentials_;
    }

    function getWithdrawalCredentials() public view returns (bytes32) {
        return (withdrawalCredentials);
    }
}