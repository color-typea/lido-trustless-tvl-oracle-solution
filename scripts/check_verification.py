import json
import os.path

from brownie.network.account import LocalAccount
from dataclasses import dataclass
import logging

from brownie.network import accounts
from brownie.exceptions import VirtualMachineError
from brownie import (GateArgument, Gate0, Gate4)
from brownie import (ProofVerifier, PlaceholderVerifier)
from brownie.network import gas_price

LOGGER = logging.getLogger("main")

CURDIR = os.path.dirname(__file__)
PROOF_BIN = os.path.join(CURDIR, "proof.bin")
CIRCUIT_PARAMS = os.path.join(CURDIR, "circuit_params.json")

@dataclass
class Contracts:
    verifier: PlaceholderVerifier
    gate: GateArgument

    def _list_with_length(self, value):
        return [len(value)] + value

    def _prepare_init_args_and_rotations(self, circuit_params):
        column_rotations = circuit_params['columns_rotations']
        init_params = [
          circuit_params["modulus"],
          circuit_params["r"],
          circuit_params["max_degree"],
          circuit_params["lambda"],

          circuit_params["rows_amount"],
          circuit_params["omega"],
      ] + \
      self._list_with_length(circuit_params["D_omegas"]) + \
      self._list_with_length(circuit_params["step_list"]) + \
      self._list_with_length(circuit_params["arithmetization_params"])

        return init_params, column_rotations

    def check_if_verifies(self, proof: bytes, circuit_params):
        init_params, column_rotations = self._prepare_init_args_and_rotations(circuit_params)
        try:
            tx = self.verifier.verify(proof, init_params, column_rotations, self.gate.address)
            return tx
        except VirtualMachineError as exc:
            raise exc


def deploy_contracts(owner) -> Contracts:
    deploy_tx_info = {"from": owner}

    verifier_lib = ProofVerifier.deploy(deploy_tx_info)
    real_verifier = PlaceholderVerifier.deploy(deploy_tx_info)

    Gate0.deploy(deploy_tx_info)
    Gate4.deploy(deploy_tx_info)
    gate = GateArgument.deploy(deploy_tx_info)

    return Contracts(real_verifier, gate)

def read_proof_and_params():
    with open(CIRCUIT_PARAMS, 'rb') as circuit_params_json:
        circuit_params = json.load(circuit_params_json)

    with open(PROOF_BIN, "r") as proof_bin_hex:
        proof_hex = proof_bin_hex.read()
        proof = bytes.fromhex(proof_hex[2:])

    return proof, circuit_params


def init() -> Contracts:
    owner = accounts[0]
    # this is needed to make brownie with hardforks newer than istanbul
    gas_price('60 gwei')

    return deploy_contracts(owner)


def main():
    contracts = init()
    proof, circuit_params = read_proof_and_params()

    print(proof.hex()[:100])

    verified = contracts.check_if_verifies(proof, circuit_params)
    if verified:
        print("Success")
    else:
        print("Failed to verify")
