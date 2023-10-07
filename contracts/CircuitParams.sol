// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

library CircuitParams {
    uint256 constant modulus = 28948022309329048855892746252171976963363056481941560715954676764349967630337;
    uint256 constant r = 2;
    uint256 constant max_degree = 7;
    uint256 constant lambda = 2;

    uint256 constant rows_amount = 8;
    uint256 constant omega = 199455130043951077247265858823823987229570523056509026484192158816218200659;

    function get_D_omegas()
    internal pure returns (uint256[2] memory) {
        uint256[2] memory D_omegas = [
            uint256(199455130043951077247265858823823987229570523056509026484192158816218200659), 
            uint256(24760239192664116622385963963284001971067308018068707868888628426778644166363)
        ];
        return (D_omegas);
    }
    function get_step_list()
    internal pure returns (uint256[2] memory) {
        uint256[2] memory step_list = [
            uint256(1), 
            uint256(1)
        ];
        return step_list;
    }

    function get_arithmetization_params()
    internal pure returns (uint256[4] memory) {
        uint256[4] memory arithmetization_params = [
            uint256(15), 
            uint256(1), 
            uint256(5), 
            uint256(15)
        ];
        return (arithmetization_params);
    }

    function get_init_params()
    internal pure returns (uint256[] memory init_params) {
        uint256[2] memory d_omegas = get_D_omegas();
        uint256[2] memory step_list = get_step_list();
        uint256[4] memory arithmetization_params = get_arithmetization_params();

        uint256[] memory init_args = new uint256[](
            6 // static fields: modulus to omega
            + (1 + d_omegas.length) // D_omegas.length + D_omegas
            + (1 + step_list.length) // step_list.length + step_list
            + (1 + arithmetization_params.length) // arithmetization_params.length + arithmetization_params
        );

        uint cur_index = 0;

        init_args[cur_index++] = modulus;
        init_args[cur_index++] = r;
        init_args[cur_index++] = max_degree;
        init_args[cur_index++] = lambda;
        init_args[cur_index++] = rows_amount;
        init_args[cur_index++] = omega;

        // Append D_omegas and length
        init_args[cur_index++] = d_omegas.length;
        for (uint idx = 0; idx < d_omegas.length; idx++) {
            init_args[cur_index++] = d_omegas[idx];
        }

        // Append step_list and length
        init_args[cur_index++] = step_list.length;
        for (uint idx = 0; idx < step_list.length; idx++) {
            init_args[cur_index++] = step_list[idx];
        }

        // Append arithmetization_params and length
        init_args[cur_index++] = arithmetization_params.length;
        for (uint idx = 0; idx < arithmetization_params.length; idx++) {
            init_args[cur_index++] = arithmetization_params[idx];
        }

        return (init_args);
    }

    function makeDyn1(int256 value) internal pure returns (int256[] memory) {
        int256[] memory rslt = new int256[](1);
        rslt[0] = value;
        return rslt;
    }

    function makeDyn3(int256 value1, int256 value2, int256 value3) internal pure returns (int256[] memory) {
        int256[] memory rslt = new int256[](3);
        rslt[0] = value1;
        rslt[1] = value2;
        rslt[2] = value3;
        return rslt;
    }

    function get_column_rotations()
    internal pure returns (int256[][] memory) {
        int256[][] memory column_rotations = new int256[][](56);
        uint idx = 0;
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        column_rotations[idx++] = makeDyn1(0);
        return column_rotations;
    }
}