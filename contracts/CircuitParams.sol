// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

library CircuitParams {
    uint256 constant modulus = 28948022309329048855892746252171976963363056481941560715954676764349967630337;
    uint256 constant r = 16;
    uint256 constant max_degree = 131071;
    uint256 constant lambda = 2;

    uint256 constant rows_amount = 131072;
    uint256 constant omega = 21090803083255360924969619711782040241928172562822879037017685322859036642027;

    function get_D_omegas()
    internal pure returns (uint256[16] memory) {
        uint256[16] memory D_omegas = [
            uint256(21090803083255360924969619711782040241928172562822879037017685322859036642027), 
            uint256(10988054172925167713694812535142550583545019937971378974362050426778203868934), 
            uint256(22762810496981275083229264712375994604562198468579727082239970810950736657129), 
            uint256(26495698845590383240609604404074423972849566255661802313591097233811292788392), 
            uint256(13175653644678658737556805326666943932741525539026001701374450696535194715445), 
            uint256(18589158034707770508497743761528839450567399299956641192723316341154428793508), 
            uint256(5207999989657576140891498154897385491612440083899963290755562031717636435093), 
            uint256(21138537593338818067112636105753818200833244613779330379839660864802343411573), 
            uint256(22954361264956099995527581168615143754787441159030650146191365293282410739685), 
            uint256(23692685744005816481424929253249866475360293751445976741406164118468705843520), 
            uint256(7356716530956153652314774863381845254278968224778478050456563329565810467774), 
            uint256(17166126583027276163107155648953851600645935739886150467584901586847365754678), 
            uint256(3612152772817685532768635636100598085437510685224817206515049967552954106764), 
            uint256(14450201850503471296781915119640920297985789873634237091629829669980153907901), 
            uint256(199455130043951077247265858823823987229570523056509026484192158816218200659), 
            uint256(24760239192664116622385963963284001971067308018068707868888628426778644166363)
        ];
        return (D_omegas);
    }
    function get_step_list()
    internal pure returns (uint256[16] memory) {
        uint256[16] memory step_list = [
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1), 
            uint256(1)
        ];
        return step_list;
    }

    function get_arithmetization_params()
    internal pure returns (uint256[4] memory) {
        uint256[4] memory arithmetization_params = [
            uint256(15), 
            uint256(5), 
            uint256(5), 
            uint256(30)
        ];
        return (arithmetization_params);
    }

    function get_init_params()
    internal pure returns (uint256[] memory init_params) {
        uint256[16] memory d_omegas = get_D_omegas();
        uint256[16] memory step_list = get_step_list();
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
        int256[][] memory column_rotations = new int256[][](55);
        uint idx = 0;
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
        column_rotations[idx++] = makeDyn3(-1, 0, 1);
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