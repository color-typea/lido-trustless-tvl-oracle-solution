from brownie.exceptions import VirtualMachineError
from dataclasses import dataclass
import logging

from brownie.network import accounts
from brownie import (
    ZKTVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock,
    BeaconBlockHashKeeper, Wei
)
from brownie.convert import to_bytes, to_address, to_bool, to_int
from eth_typing import HexStr

import secrets

from typing import Iterator

from scripts.eth_node_api_stub_server import StubEthApiServer
from scripts.eth_consensus_layer_ssz import BeaconStateModifier, BeaconState
from scripts.eth_ssz_utils import make_validator, make_beacon_block_state, Constants

LOGGER = logging.getLogger("main")


@dataclass
class BeaconBlockHashRecord:
    slot: int
    block_hash: bytes

    @property
    def epoch(self):
        return self.slot // 32

    def hash_str(self):
        return self.block_hash.hex()

    def to_block_hash_keeper_call(self):
        return (self.slot, self.block_hash)


@dataclass
class Contracts:
    verifier: ZKLLVMVerifierMock
    lido_locator: LidoLocatorMock
    lido_staking_router: LidoStakingRouterMock
    block_hash_keeper: BeaconBlockHashKeeper
    tvl_contract: ZKTVLOracleContract
    verification_gate: HexStr

    def set_verifier_mock(self, passes=False):
        self.verifier.setPass(passes)

        passes_check = to_bool(self.verifier.verify(b'01' * 32, [], [], self.verification_gate))
        try:
            assert passes_check == passes
        except AssertionError as e:
            print(f"Contract: {passes_check}")
            print(f"Expected: {passes}")

    def update_block_hash(self, next_beacon_block_hash: BeaconBlockHashRecord):
        print(f"Updating block hash for {next_beacon_block_hash}")
        self.block_hash_keeper.setBeaconBlockHash(next_beacon_block_hash.to_block_hash_keeper_call(), {})

        block_hash_bytes = to_bytes(self.block_hash_keeper.getBeaconBlockHash(next_beacon_block_hash.slot))
        try:
            assert (to_bytes(block_hash_bytes) == next_beacon_block_hash.block_hash)
        except AssertionError as e:
            print(f"Contract: {block_hash_bytes.hex()}")
            print(f"Expected: {next_beacon_block_hash.block_hash.hex()}")
            raise e


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


@dataclass
class OracleProof:
    beaconBlockHash: bytes
    zkProof: bytes

    def to_contract_call(self):
        return (self.beaconBlockHash, self.zkProof)


def deploy_contracts(owner, withdrawal_credentials: bytes, verification_gate: HexStr) -> Contracts:
    deploy_tx_info = {"from": owner}
    verifier = ZKLLVMVerifierMock.deploy(deploy_tx_info)
    staking_router = LidoStakingRouterMock.deploy(withdrawal_credentials, deploy_tx_info)
    locator = LidoLocatorMock.deploy(staking_router.address, deploy_tx_info)
    hash_keeper = BeaconBlockHashKeeper.deploy(deploy_tx_info)
    tvl_oracle_contract = ZKTVLOracleContract.deploy(
        verifier.address, verification_gate, hash_keeper.address, locator.address, deploy_tx_info
    )

    return Contracts(verifier, locator, staking_router, hash_keeper, tvl_oracle_contract, verification_gate)


def gen_block_hashes() -> Iterator[BeaconBlockHashRecord]:
    slot_number = 1
    while True:
        next_hash = secrets.token_bytes(32)
        yield BeaconBlockHashRecord(slot_number, next_hash)
        slot_number += 1


class WithdrawalCredentials:
    LIDO = b'\x01\x02' * 16
    OTHER = b'\xff' * 32


class DI:
    def __init__(self):
        self._contracts = None
        self._server = None

    @property
    def contracts(self) -> Contracts:
        return self._contracts

    @contracts.setter
    def contracts(self, value: Contracts):
        self._contracts = value

    @property
    def server(self) -> StubEthApiServer:
        return self._server

    @server.setter
    def server(self, value: StubEthApiServer):
        self._server = value


container = DI()

CONTRACT_VERSION = 1

def main():
    container.server = StubEthApiServer()
    print("Starting server")
    container.server.start_nonblocking()
    print("Server started")

    owner = accounts[0]
    oracle_operator = accounts[1]
    verification_gate = HexStr(secrets.token_hex(20))
    print(f"Verification gate: {verification_gate}\nWithdrawal credentials: {WithdrawalCredentials.LIDO.hex()}")

    container.contracts = deploy_contracts(owner, WithdrawalCredentials.LIDO, verification_gate)

    # deployment and  sanity check
    assert to_bytes(container.contracts.lido_staking_router.getWithdrawalCredentials()) == WithdrawalCredentials.LIDO
    assert to_address(container.contracts.lido_locator.stakingRouter()) == container.contracts.lido_staking_router.address

    hash_sequence = gen_block_hashes()

    print("Adding initial state")
    initial_validators = (
            [make_validator(WithdrawalCredentials.LIDO, 0, 1, None) for _ in range(10)] +
            [make_validator(WithdrawalCredentials.OTHER, 0, 1, None) for _ in range(5)]
    )
    initial_balances = [(idx + 1) * (10 ** 9) for idx in range(len(initial_validators))]

    block1_meta = next(hash_sequence)
    bs1 = make_beacon_block_state(
        block1_meta.slot, block1_meta.epoch, Constants.Genesis.BLOCK_ROOT, initial_validators, initial_balances
    )
    report1 = step1_success(block1_meta, bs1)
    input(f"At slot {block1_meta.slot} - press any key to progress")

    block2_meta = next(hash_sequence)
    bs2 = BeaconStateModifier(bs1).update_balance(0, 1234567890).update_balance(7, 10).get()
    step2_fail_verifier_rejects(block2_meta, bs2, report1)
    input(f"At slot {block2_meta.slot} - press any key to progress")

    block3_meta = next(hash_sequence)
    bs3 = BeaconStateModifier(bs2).modify_validator_fields(0, {"slashed": True}).get()
    step3_fail_wrong_withdrawal_credentials(block3_meta, bs3, finalized_slot=block2_meta.slot, expect_report=report1)
    input(f"At slot {block3_meta.slot} - press any key to progress")

    block4_meta = next(hash_sequence)
    bs4 = BeaconStateModifier(bs3).update_balance(1, bs3.balances[1] + 2 * 10 ** 9).get()
    report4 = step4_fail_wrong_beacon_block_hash(block4_meta, bs4, expected_report=report1)
    input(f"At slot {block4_meta.slot} - press any key to resubmit with correct hash")
    step4_success(block4_meta, submit_report=report4, expected_report=report4)
    input(f"At slot {block4_meta.slot} - press any key to progress")

    container.server.terminate()
    print("The End")


def step1_success(block_meta, bs1: BeaconState):
    container.server.add_state(block_meta.slot, block_meta.block_hash, bs1)
    container.server.set_chain_pointers(head=block_meta.slot, finalized=block_meta.slot, justified=block_meta.slot)
    container.contracts.update_block_hash(block_meta)
    container.contracts.set_verifier_mock(passes=True)

    report1 = OracleReport(block_meta.slot, block_meta.epoch, WithdrawalCredentials.LIDO, 10, 1, Wei(2 * 10 ** 18))
    proof = OracleProof(block_meta.block_hash, bytes.fromhex("abcdef"))

    container.contracts.tvl_contract.submitReportData(report1.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION)
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())

    assert latest_report == report1
    print("Report1 accepted")
    return report1


def step2_fail_verifier_rejects(block_meta, state: BeaconState, expected_report: OracleReport):
    container.server.add_state(block_meta.slot, block_meta.block_hash, state)
    container.server.set_chain_pointers(head=block_meta.slot)
    container.contracts.update_block_hash(block_meta)
    container.contracts.set_verifier_mock(passes=False)

    report2 = OracleReport(
        block_meta.slot, block_meta.epoch, WithdrawalCredentials.LIDO, 0, 100, Wei(10000)
    )
    proof = OracleProof(block_meta.block_hash, bytes.fromhex("abcdef"))

    try:
        container.contracts.tvl_contract.submitReportData(report2.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION)
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert latest_report == expected_report, "Report was unexpectedly updated"
    print("Report 2 rejected - verifier rejects")
    return report2


def step3_fail_wrong_withdrawal_credentials(
        block_meta, state: BeaconState, finalized_slot: int, expect_report: OracleReport
):
    container.server.add_state(block_meta.slot, block_meta.block_hash, state)
    container.server.set_chain_pointers(head=block_meta.slot, finalized=finalized_slot)
    container.contracts.update_block_hash(block_meta)
    container.contracts.set_verifier_mock(passes=True)

    report3 = OracleReport(block_meta.slot, block_meta.epoch, WithdrawalCredentials.OTHER, 0, 100, Wei(10000))
    proof = OracleProof(block_meta.block_hash, bytes.fromhex("abcdef"))

    try:
        container.contracts.tvl_contract.submitReportData(report3.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION)
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert latest_report == expect_report, "Report was unexpectedly updated"
    print("Report 3 rejected - wrong invalid credentials")
    return report3


def step4_fail_wrong_beacon_block_hash(
        block_meta: BeaconBlockHashRecord, bs4: BeaconState, expected_report: OracleReport
):
    container.server.add_state(block_meta.slot, block_meta.block_hash, bs4)
    container.server.set_chain_pointers(head=block_meta.slot, finalized=block_meta.slot, justified=block_meta.slot)

    container.contracts.update_block_hash(block_meta)
    container.contracts.set_verifier_mock(passes=True)

    report4 = OracleReport(block_meta.slot, block_meta.epoch, WithdrawalCredentials.LIDO, 0, 100, Wei(10000))
    proof = OracleProof(b'\x00' * 32, bytes.fromhex("abcdef"))
    try:
        container.contracts.tvl_contract.submitReportData(report4.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION)
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert latest_report == expected_report, "Report was unexpectedly updated"
    print("Report 4 rejected - wrong beacon block hash")
    return report4


def step4_success(block_meta, submit_report: OracleReport, expected_report: OracleReport):
    print("Resubmitting report4 with correct hash")
    proof = OracleProof(block_meta.block_hash, bytes.fromhex("abcdef"))
    container.contracts.tvl_contract.submitReportData(submit_report.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION)
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert latest_report == expected_report
    print("Report4 accepted")
