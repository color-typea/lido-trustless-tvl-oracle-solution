// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

library CircuitParams {
    uint256 constant modulus = 28948022309329048855892746252171976963363056481941560715954676764349967630337;
    uint256 constant r = 17;
    uint256 constant maxDegree = 262143;
    uint256 constant lambda = 2;

    uint256 constant rowsAmount = 262144;
    uint256 constant omega = 1052476823299314129969668407141491286911278219597830940957003018745899426804;

    function getDOmegas()
    internal pure returns (uint256[17] memory DOmegas) {
        DOmegas = [
            uint256(1052476823299314129969668407141491286911278219597830940957003018745899426804), 
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
    }

    function getStepList()
    internal pure returns (uint256[17] memory stepList) {
        stepList = [
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
            uint256(1), 
            uint256(1)
        ];
    }

    function getArithmetizationParams()
    internal pure returns (uint256[4] memory arithmetizationParams) {
        arithmetizationParams = [
            uint256(15), 
            uint256(1), 
            uint256(5), 
            uint256(15)
        ];
    }

    function getInitParams()
    internal pure returns (uint256[] memory initArgs) {
        uint256[17] memory dOmegas = getDOmegas();
        uint256[17] memory stepList = getStepList();
        uint256[4] memory arithmetizationParams = getArithmetizationParams();

        initArgs = new uint256[](
            6 // static fields: modulus to omega
            + (1 + dOmegas.length) // D_omegas.length + D_omegas
            + (1 + stepList.length) // step_list.length + step_list
            + (1 + arithmetizationParams.length) // arithmetization_params.length + arithmetization_params
        );

        uint curIndex = 0;

        initArgs[curIndex++] = modulus;
        initArgs[curIndex++] = r;
        initArgs[curIndex++] = maxDegree;
        initArgs[curIndex++] = lambda;
        initArgs[curIndex++] = rowsAmount;
        initArgs[curIndex++] = omega;

        // Append D_omegas and length
        initArgs[curIndex++] = dOmegas.length;
        for (uint idx = 0; idx < dOmegas.length; idx++) {
            initArgs[curIndex++] = dOmegas[idx];
        }

        // Append step_list and length
        initArgs[curIndex++] = stepList.length;
        for (uint idx = 0; idx < stepList.length; idx++) {
            initArgs[curIndex++] = stepList[idx];
        }

        // Append arithmetization_params and length
        initArgs[curIndex++] = arithmetizationParams.length;
        for (uint idx = 0; idx < arithmetizationParams.length; idx++) {
            initArgs[curIndex++] = arithmetizationParams[idx];
        }
    }


    function dynArray1(
        int256 value0
    ) internal pure returns (int256[] memory result) {
        result = new int256[](1);
        result[0] = value0;
    }

    function dynArray3(
        int256 value0,
        int256 value1,
        int256 value2
    ) internal pure returns (int256[] memory result) {
        result = new int256[](3);
        result[0] = value0;
        result[1] = value1;
        result[2] = value2;
    }


    function getColumnRotations()
    internal pure returns (int256[][] memory) {
        int256[][] memory column_rotations = new int256[][](56);
        uint idx = 0;
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray3(-1, 0, 1);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        column_rotations[idx++] = dynArray1(0);
        return column_rotations;
    }
}