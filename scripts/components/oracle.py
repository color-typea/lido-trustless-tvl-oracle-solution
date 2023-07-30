from dataclasses import dataclass
from brownie.convert import to_bytes, to_address, to_bool, to_int

from typing import List, Tuple
from dataclasses import dataclass

from scripts.components.concensus_client import BeaconBlockHashRecord
from scripts.components.eth_consensus_layer_ssz import Validator, BeaconState


class WithdrawalCredentials:
    # LIDO = b'\x01\x02' * 16
    LIDO = bytes.fromhex("010000000000000000000000b9d7934878b5fb9610b3fe8a5e441e8fad7e293f")
    OTHER = b'\xff' * 32

@dataclass
class OracleReport:
    slot: int
    epoch: int
    lidoWithdrawalCredentials: bytes
    activeValidators: int
    exitedValidators: int
    totalValueLocked: int

    def to_contract_call(self):
        return (self.slot, self.epoch, self.lidoWithdrawalCredentials, self.activeValidators, self.exitedValidators,
                self.totalValueLocked)

    @classmethod
    def reconstruct_from_contract(cls, raw_values):
        return cls(
            slot=to_int(raw_values[0]),
            epoch=to_int(raw_values[1]),
            lidoWithdrawalCredentials=to_bytes(raw_values[2]),
            activeValidators=to_int(raw_values[3]),
            exitedValidators=to_int(raw_values[4]),
            totalValueLocked=to_int(raw_values[5]),
        )

    @classmethod
    def compute_expected(
            cls, block_data: BeaconBlockHashRecord, withdrawal_credentials: bytes, beacon_state: BeaconState
    ) -> 'OracleReport':
        balance, active, exited = 0, 0, 0
        for (idx, validator) in enumerate(beacon_state.validators):
            if validator.withdrawal_credentials != WithdrawalCredentials.LIDO:
                continue

            if validator.exit_epoch <= block_data.epoch:
                exited += 1
            if validator.activation_eligibility_epoch <= block_data.epoch:
                active += 1
            validator_balance = beacon_state.balances[idx]
            balance += validator_balance

        return cls(
            slot=block_data.slot,
            epoch=block_data.epoch,
            lidoWithdrawalCredentials=withdrawal_credentials,
            activeValidators=active,
            exitedValidators=exited,
            totalValueLocked=balance
        )

    def __str__(self):
        return f"OracleReport(slot={self.slot}, epoch={self.epoch}, " \
               f"lidoWithdrawalCredentials={self.lidoWithdrawalCredentials.hex()[:5]}...{self.lidoWithdrawalCredentials.hex()[-6:]}, " \
               f"activeValidators={self.activeValidators}, " \
               f"exitedValidators={self.exitedValidators}, " \
               f"totalValueLocked={self.totalValueLocked} Gwei)"


@dataclass
class OracleProof:
    beaconBlockHash: bytes
    zkProof: bytes

    def to_contract_call(self):
        return (self.beaconBlockHash, self.zkProof)




@dataclass
class BeaconStateSummary:
    label: str
    balances: List[int]
    validator_states: List[Tuple[str, str]]

    @classmethod
    def compute(cls, label: str, block_data: BeaconBlockHashRecord, state: BeaconState) -> 'BeaconStateSummary':
        validator_states = [
            (
                validator_state_for_print(validator, block_data),
                "Lido" if validator.withdrawal_credentials == WithdrawalCredentials.LIDO else "Other"
            ) for validator in state.validators
        ]
        return cls(
            label=label, balances=list(state.balances), validator_states=validator_states
        )

    def difference(self, other: 'BeaconStateSummary') -> List[str]:
        result = []
        for idx in range(len(self.balances)):
            this_balance = self.balances[idx]
            other_balance = other.balances[idx]
            if this_balance != other_balance:
                result.append(f"Balance@{idx:02}: {this_balance - other_balance}")
        for idx in range(len(self.balances), len(other.balances)):
            result.append(f"New balance@{idx:02}: {other.balances[idx]}")

        for idx in range(len(self.validator_states)):
            this_state, this_is_lido = self.validator_states[idx]
            other_state, other_is_lido = other.validator_states[idx]
            if this_state != other_state:
                result.append(f"Validator@{idx:02} changed state: to {this_state}")
            if this_is_lido != other_is_lido:
                result.append(f"Validator@{idx:02} changed 'ownership' to {this_is_lido}")
        for idx in range(len(self.validator_states), len(other.validator_states)):
            result.append(f"New validator@{idx:02}: {other.validator_states[idx]}")

        return result

    def print_difference(self, other: 'BeaconStateSummary', printer):
        printer.info(f"BeaconState changes between {self.label} (new) and {other.label} (old):")
        for line in self.difference(other):
            printer.detail(line)

    def __str__(self):
        result = []
        result.append("|Index|State   |Is Lido|Balance    |")
        for (idx, data) in enumerate(zip(self.balances, self.validator_states)):
            balance, validator_tuple = data
            state, is_lido = validator_tuple
            bal = balance / 10 ** 9
            result.append(f"|{idx:5}|{state:8}|{is_lido:7}|{bal:7}Gwei|")

        result.append("|Index|State   |Is Lido|Balance    |")

        return "\n".join(result)

def validator_state_for_print(validator: Validator, block_data: BeaconBlockHashRecord):
    if validator.exit_epoch <= block_data.epoch:
        return "EXITED"
    elif validator.activation_eligibility_epoch <= block_data.epoch:
        return "ACTIVE"
    else:
        return "PENDING"


