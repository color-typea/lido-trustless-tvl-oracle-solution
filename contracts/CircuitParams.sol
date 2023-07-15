// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

library CircuitParams {
    // TODO: codegen from circuit_params.json
    uint256 constant modulus = 28948022309329048855892746252171976963363056481941560715954676764349967630337;
    uint256 constant r = 10;
    uint256 constant max_degree = 2047;
    uint256 constant lambda = 2;

    uint256 constant rows_amount = 2048;
    uint256 constant omega = 5207999989657576140891498154897385491612440083899963290755562031717636435093;

    function get_D_omegas()
    internal pure returns (uint256[10] memory) {
        uint256[10] memory D_omegas = [
            uint256(5207999989657576140891498154897385491612440083899963290755562031717636435093),
            uint256(21138537593338818067112636105753818200833244613779330379839660864802343411573),
            uint256(22954361264956099995527581168615143754787441159030650146191365293282410739685),
            uint256(23692685744005816481424929253249866475360293751445976741406164118468705843520),
            uint256(7356716530956153652314774863381845254278968224778478050456563329565810467774),
            uint256(17166126583027276163107155648953851600645935739886150467584901586847365754678),
            uint256(3612152772817685532768635636100598085437510685224817206515049967552954106764),
            uint256(14450201850503471296781915119640920297985789873634237091629829669980153907901),
            uint256(199455130043951077247265858823823987229570523056509026484192158816218200659),
            uint256(2476023919266411662238596396328400197106730801806870786888862842677864416636)
        ];
        return (D_omegas);
    }
    function get_step_list()
    internal pure returns (uint256[10] memory) {
        uint256[10] memory step_list = [uint256(1), uint256(1), uint256(1), uint256(1), uint256(1), uint256(1), uint256(1), uint256(1), uint256(1), uint256(1)];
        return step_list;
    }

    function get_arithmetization_params()
    internal pure returns (uint256[4] memory) {
        uint256[4] memory arithmetization_params = [uint256(15), uint256(5), uint256(5), uint256(30)];
        return (arithmetization_params);
    }

    function get_init_params()
    internal pure returns (uint256[] memory init_params) {
        uint256[10] memory d_omegas = get_D_omegas();
        uint256[10] memory step_list = get_step_list();
        uint256[4] memory arithmetization_params = get_arithmetization_params();

        uint256[] memory init_args = new uint256[](
            6 // static fields: modulus to omega
            + (d_omegas.length + 1) // D_omegas.length + D_omegas
            + (step_list.length + 1) // step_list.length + step_list
            + (arithmetization_params.length + 1) // arithmetization_params.length + arithmetization_params
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

    function get_column_rotations()
    internal pure returns (int256[][] memory) {
        int256[][] memory column_rotations = new int256[][](0);
        return (column_rotations);
    }

//    function get_column_rotations()
//    internal pure returns (uint256[][] memory column_rotations) {
//
//        column_rotations = [
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([- 1, 0, 1]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0]),
//            uint256[]([0])
//        ];
//    }
}