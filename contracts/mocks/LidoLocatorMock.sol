// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

import "../../interfaces/ILidoLocator.sol";


contract LidoLocatorMock is ILidoLocator {
    address stakingModule;
    constructor(address stakingModule_) {
        stakingModule = stakingModule_;
    }

    function stakingRouter() external view returns(address) {
        return (stakingModule);
    }
}