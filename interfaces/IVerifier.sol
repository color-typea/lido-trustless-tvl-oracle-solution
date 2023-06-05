// SPDX-License-Identifier: Apache-2.0.

pragma solidity ^0.8.0;

// ZKLLVM's verifier
// https://github.com/NilFoundation/evm-placeholder-verification/blob/master/contracts/interfaces/verifier.sol
interface IVerifier {
    function verify(
        bytes calldata blob,
        uint256[]  calldata init_params,
        int256[][] calldata columns_rotations,
        address gate_argument
    ) external view returns (bool);
}