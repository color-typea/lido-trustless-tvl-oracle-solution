// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8 <0.9;

import "../../interfaces/IVerifier.sol";

contract ZKLLVMVerifierMock is IVerifier {
    bool passCheck;

    function setPass(bool pass) public {
        passCheck = pass;
    }

    function verify(
        bytes calldata blob,
        uint256[]  calldata init_params,
        int256[][] calldata columns_rotations,
        address gate_argument
    ) public view returns (bool) {
        return (passCheck);
    }
}