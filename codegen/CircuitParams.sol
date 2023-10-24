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
    internal pure returns (uint256[{{D_omegas_len}}] memory DOmegas) {
        DOmegas = [
{%- for d_omega in D_omegas %}
            uint256({{d_omega}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
    }

    function getStepList()
    internal pure returns (uint256[{{step_list_len}}] memory stepList) {
        stepList = [
{%- for step in step_list %}
            uint256({{step}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
    }

    function getArithmetizationParams()
    internal pure returns (uint256[{{arithmetization_params_len}}] memory arithmetizationParams) {
        arithmetizationParams = [
{%- for param in arithmetization_params %}
            uint256({{param}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
    }

    function getInitParams()
    internal pure returns (uint256[] memory initArgs) {
        uint256[{{D_omegas_len}}] memory dOmegas = getDOmegas();
        uint256[{{step_list_len}}] memory stepList = getStepList();
        uint256[{{arithmetization_params_len}}] memory arithmetizationParams = getArithmetizationParams();

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

{% for length in present_column_rotation_lengths %}
    function dynArray{{length}}(
{%- for i in range(length) %}
        int256 value{{i}}{% if not loop.last %},{% endif %}
{%- endfor %}
    ) internal pure returns (int256[] memory result) {
        result = new int256[]({{length}});
{%- for i in range(length) %}
        result[{{i}}] = value{{i}};
{%- endfor %}
    }
{% endfor %}

    function getColumnRotations()
    internal pure returns (int256[][] memory) {
        int256[][] memory column_rotations = new int256[][]({{columns_rotations_len}});
        uint idx = 0;
{%- for column_rotation in columns_rotations %}
        column_rotations[idx++] = dynArray{{column_rotation|length}}({{column_rotation|join(', ')}});
{%- endfor %}
        return column_rotations;
    }
}