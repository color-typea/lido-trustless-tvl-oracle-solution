import json
import os
from jinja2 import Template
import typed_argparse as tap

CURDIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.dirname(CURDIR)

class ArgumentParser(tap.TypedArgs):
    circuit_params: str = tap.arg('-c')
    output: str = tap.arg('-o', default="../contracts/CircuitParams.sol")


def main(args: ArgumentParser):
    with open(os.path.join(PROJECT_DIR, args.circuit_params), "r") as circuit_params_json_file:
        circuit_params_json = json.load(circuit_params_json_file)

    print(circuit_params_json)
    with open(os.path.join(CURDIR, "CircuitParams.sol")) as template_file:
        template = Template(template_file.read())

    output = template.render(
        **circuit_params_json
    )

    with open(os.path.join(CURDIR, args.output), "w") as output_file:
        output_file.write(output)

if __name__ == '__main__':
    tap.Parser(ArgumentParser).bind(main).run()