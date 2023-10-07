import dataclasses

from typing import List

import json
import os
from jinja2 import Template
import typed_argparse as tap

CURDIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.dirname(CURDIR)

@dataclasses.dataclass
class TemplateInput:
    modulus: int
    r: int
    max_degree: int
    lambdda: int  # lambda is a keyword in python
    rows_amount: int
    omega: int

    D_omegas: List[float]
    step_list: List[float]
    arithmetization_params: List[float]
    columns_rotations: List[float]

    @classmethod
    def read_from_circuit_params_json(cls, json_data):
        return cls(
            modulus = json_data['modulus'],
            omega=json_data['omega'],
            rows_amount=json_data['rows_amount'],
            columns_rotations=json_data['columns_rotations_node'],
            arithmetization_params=json_data['ar_params'],

            r = json_data['commitment_params_node']['r'],
            max_degree = json_data['commitment_params_node']['max_degree'],
            lambdda = json_data['commitment_params_node']['lambda'],
            D_omegas = json_data['commitment_params_node']['D_omegas'],
            step_list = json_data['commitment_params_node']['step_list'],
        )

    def to_template(self):
        return dataclasses.asdict(self)


class ArgumentParser(tap.TypedArgs):
    circuit_params: str = tap.arg('-c', default=os.path.join(CURDIR, '../contracts/gates/circuit_params.json'))
    output: str = tap.arg('-o', default=os.path.join(CURDIR, "../contracts/CircuitParams.sol"))


def main(args: ArgumentParser):
    with open(os.path.join(PROJECT_DIR, args.circuit_params), "r") as circuit_params_json_file:
        circuit_params_json = json.load(circuit_params_json_file)

    with open(os.path.join(CURDIR, "CircuitParams.sol")) as template_file:
        template = Template(template_file.read())

    template_input = TemplateInput.read_from_circuit_params_json(circuit_params_json)
    output = template.render(template_input.to_template())

    with open(os.path.join(CURDIR, args.output), "w") as output_file:
        output_file.write(output)

if __name__ == '__main__':
    tap.Parser(ArgumentParser).bind(main).run()