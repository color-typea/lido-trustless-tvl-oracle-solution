// SPDX-FileCopyrightText: 2023 Lido <info@lido.fi>
// SPDX-License-Identifier: GPL-3.0

// See contracts/COMPILERS.md
// solhint-disable-next-line
pragma solidity >=0.8.4;

// https://github.com/lidofinance/lido-dao/blob/master/contracts/common/interfaces/ILidoLocator.sol
// Partial interface, only including things we actually need
interface ILidoLocator {
    function stakingRouter() external view returns(address);
}