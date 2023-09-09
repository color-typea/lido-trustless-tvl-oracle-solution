// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.4;

{%- set D_omegas_len = D_omegas|length %}
{%- set step_list_len = step_list|length %}
{%- set arithmetization_params_len = arithmetization_params|length %}
{%- set columns_rotations_len = columns_rotations|length %}

library CircuitParams {
    uint256 constant modulus = {{modulus}};
    uint256 constant r = {{r}};
    uint256 constant max_degree = {{max_degree}};
    uint256 constant lambda = {{lambda}};

    uint256 constant rows_amount = {{rows_amount}};
    uint256 constant omega = {{omega}};

    function get_D_omegas()
    internal pure returns (uint256[{{D_omegas_len}}] memory) {
        uint256[{{D_omegas_len}}] memory D_omegas = [
{%- for d_omega in D_omegas %}
            uint256({{d_omega}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
        return (D_omegas);
    }
    function get_step_list()
    internal pure returns (uint256[{{step_list_len}}] memory) {
        uint256[{{step_list_len}}] memory step_list = [
{%- for step in step_list %}
            uint256({{step}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
        return step_list;
    }

    function get_arithmetization_params()
    internal pure returns (uint256[{{arithmetization_params_len}}] memory) {
        uint256[{{arithmetization_params_len}}] memory arithmetization_params = [
{%- for param in arithmetization_params %}
            uint256({{param}}){% if not loop.last %}, {% endif %}
{%- endfor %}
        ];
        return (arithmetization_params);
    }

    function get_init_params()
    internal pure returns (uint256[] memory init_params) {
        uint256[{{D_omegas_len}}] memory d_omegas = get_D_omegas();
        uint256[{{step_list_len}}] memory step_list = get_step_list();
        uint256[{{arithmetization_params_len}}] memory arithmetization_params = get_arithmetization_params();

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
        int256[][] memory column_rotations = new int256[][]({{columns_rotations_len}});
        uint idx = 0;
{%- for column_rotation in columns_rotations -%}
    {% if column_rotation|length == 3 %}
        column_rotations[idx++] = makeDyn3({{column_rotation|join(', ')}});
    {%- elif column_rotation|length == 1 %}
        column_rotations[idx++] = makeDyn1({{column_rotation[0]}});
    {%- endif %}
{%- endfor %}
        return column_rotations;
    }
}