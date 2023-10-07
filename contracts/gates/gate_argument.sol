
// SPDX-License-Identifier: Apache-2.0.
//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova  <alalmoskvin@nil.foundation>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//---------------------------------------------------------------------------//
pragma solidity >=0.8.4;

import "@nilfoundation/evm-placeholder-verification/contracts/types.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/basic_marshalling.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/commitments/batched_lpc_verifier.sol";
import "@nilfoundation/evm-placeholder-verification/contracts/interfaces/gate_argument.sol";

contract gates_gate_argument_split_gen  is IGateArgument{
    uint256 constant GATES_N = 1;

    struct local_vars_type{
        // 0x0
        uint256 constraint_eval;
        // 0x20
        uint256 gate_eval;
        // 0x40
        uint256 gates_evaluation;
        // 0x60
        uint256 theta_acc;

		//0x80
		uint256[] witness_evaluations;
		//a0
		uint256[] selector_evaluations;

    }

    uint256 constant MODULUS_OFFSET = 0x0;
    uint256 constant THETA_OFFSET = 0x20;

    uint256 constant CONSTRAINT_EVAL_OFFSET = 0x00;
    uint256 constant GATE_EVAL_OFFSET = 0x20;
    uint256 constant GATES_EVALUATIONS_OFFSET = 0x40;
    uint256 constant THETA_ACC_OFFSET = 0x60;
	uint256 constant WITNESS_EVALUATIONS_OFFSET = 0x80;
	uint256 constant SELECTOR_EVALUATIONS_OFFSET = 0xa0;


    function evaluate_gates_be(
        bytes calldata blob,
        uint256 eval_proof_combined_value_offset,
        types.gate_argument_params memory gate_params,
        types.arithmetization_params memory ar_params,
        int256[][] calldata columns_rotations
    ) external pure returns (uint256 gates_evaluation) {
        local_vars_type memory local_vars;


        local_vars.witness_evaluations = new uint256[](ar_params.witness_columns);
        for (uint256 i = 0; i < ar_params.witness_columns;) {
            local_vars.witness_evaluations[i] = batched_lpc_verifier.get_variable_values_z_i_j_from_proof_be(
                    blob, eval_proof_combined_value_offset, i, 0
            );
            unchecked{i++;}
        }

        local_vars.selector_evaluations = new uint256[](ar_params.selector_columns);
        for (uint256 i = 0; i < ar_params.selector_columns;) {
            local_vars.selector_evaluations[i] = batched_lpc_verifier.get_fixed_values_z_i_j_from_proof_be(
                blob, eval_proof_combined_value_offset, ar_params.permutation_columns + ar_params.permutation_columns + ar_params.constant_columns + i, 0
            );
            unchecked{i++;}
        }


        local_vars.theta_acc = 1;
        local_vars.gates_evaluation = 0;    

        uint256 theta_acc = local_vars.theta_acc;

        uint256 terms;
        assembly {
            let modulus := mload(gate_params)
            let theta := mload(add(gate_params, THETA_OFFSET))


            function get_witness_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, WITNESS_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

            function get_selector_i(idx, ptr) -> result {
                result := mload(add(add(mload(add(ptr, SELECTOR_EVALUATIONS_OFFSET)), 0x20), mul(0x20, idx)))
            }

			//Gate0
			mstore(add(local_vars, GATE_EVAL_OFFSET), 0)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)
			terms:=0x40000000000000000000000000000000224698fc094cf91b992d30ed00000000
			terms:=mulmod(terms, get_witness_i(2, local_vars), modulus)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=get_witness_i(1, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			terms:=get_witness_i(0, local_vars)
			mstore(add(local_vars, CONSTRAINT_EVAL_OFFSET),addmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),terms,modulus))
			mstore(add(local_vars, GATE_EVAL_OFFSET),addmod(mload(add(local_vars, GATE_EVAL_OFFSET)),mulmod(mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),theta_acc,modulus),modulus))
			theta_acc := mulmod(theta_acc, theta, modulus)
			mstore(add(local_vars, GATE_EVAL_OFFSET),mulmod(mload(add(local_vars, GATE_EVAL_OFFSET)),get_selector_i(0,local_vars),modulus))
			gates_evaluation := addmod(gates_evaluation,mload(add(local_vars, GATE_EVAL_OFFSET)),modulus)


        }
    }
}
