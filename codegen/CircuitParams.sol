// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

{%- set D_omegas_len = D_omegas|length %}
{%- set step_list_len = step_list|length %}
{%- set arithmetization_params_len = arithmetization_params|length %}
{%- set columns_rotations_len = columns_rotations|length %}

library CircuitParams {
    uint256 constant modulus = {{modulus}};
    uint256 constant r = {{r}};
    uint256 constant maxDegree = {{max_degree}};
    uint256 constant lambda = {{lambdda}};

    uint256 constant rowsAmount = {{rows_amount}};
    uint256 constant omega = {{omega}};

    function getDOmegas()
    internal pure returns (uint256[{{D_omegas_len}}] memory) {
        uint256[{{D_omegas_len}}] memory DOmegas = [
{%- for d_omega in D_omegas %}
            uint256({{d_omega}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
        return (DOmegas);
    }
    function getStepList()
    internal pure returns (uint256[{{step_list_len}}] memory) {
        uint256[{{step_list_len}}] memory stepList = [
{%- for step in step_list %}
            uint256({{step}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
        return stepList;
    }

    function getArithmetizationParams()
    internal pure returns (uint256[{{arithmetization_params_len}}] memory) {
        uint256[{{arithmetization_params_len}}] memory arithmetizationParams = [
{%- for param in arithmetization_params %}
            uint256({{param}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
        return (arithmetizationParams);
    }

    function getInitParams()
    internal pure returns (uint256[] memory) {
        uint256[{{D_omegas_len}}] memory dOmegas = getDOmegas();
        uint256[{{step_list_len}}] memory stepList = getStepList();
        uint256[{{arithmetization_params_len}}] memory arithmetizationParams = getArithmetizationParams();

        uint256[] memory initArgs = new uint256[](
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

        return (initArgs);
    }

    function makeDyn1(int256 value) internal pure returns (int256[] memory) {
        int256[] memory rslt = new int256[](1);
        rslt[0] = value;
        return rslt;
    }

    function makeDyn2(int256 value1, int256 value2) internal pure returns (int256[] memory) {
        int256[] memory rslt = new int256[](2);
        rslt[0] = value1;
        rslt[1] = value2;
        return rslt;
    }

    function makeDyn3(int256 value1, int256 value2, int256 value3) internal pure returns (int256[] memory) {
        int256[] memory rslt = new int256[](3);
        rslt[0] = value1;
        rslt[1] = value2;
        rslt[2] = value3;
        return rslt;
    }

    function getColumnRotations()
    internal pure returns (int256[][] memory) {
        int256[][] memory column_rotations = new int256[][]({{columns_rotations_len}});
        uint idx = 0;
{%- for column_rotation in columns_rotations -%}
    {% if column_rotation|length == 3 %}
        column_rotations[idx++] = makeDyn3({{column_rotation|join(', ')}});
    {%- elif column_rotation|length == 2 %}
        column_rotations[idx++] = makeDyn2({{column_rotation|join(', ')}});
    {%- elif column_rotation|length == 1 %}
        column_rotations[idx++] = makeDyn1({{column_rotation[0]}});
    {%- endif %}
{%- endfor %}
        return column_rotations;
    }
}