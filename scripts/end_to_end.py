import subprocess

import os

import requests
from brownie.exceptions import VirtualMachineError
from brownie.network.account import LocalAccount
from dataclasses import dataclass
import logging

from brownie.network import accounts
from brownie import (
    ZKTVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock,
    BeaconBlockHashKeeper, Wei,
    GateArgument
)
from brownie import (ProofVerifier, PlaceholderVerifier)
from brownie.network import gas_price
from brownie.network.gas.strategies import LinearScalingStrategy

from brownie.convert import to_bytes, to_address, to_bool, to_int
from eth_typing import HexStr

import secrets
from hexbytes import HexBytes

from typing import Iterator, List

from scripts.components.oracle_invoker import OracleInvoker, OracleInvokerEnv
from scripts.components.eth_node_api_stub_server import StubEthApiServer
from scripts.components.eth_consensus_layer_ssz import BeaconStateModifier, BeaconState, Balances
from scripts.components.eth_ssz_utils import make_validator, make_beacon_block_state, Constants

LOGGER = logging.getLogger("main")


@dataclass
class BeaconBlockHashRecord:
    slot: int
    block_hash: HexBytes

    @property
    def epoch(self):
        return self.slot // 32

    def hash_str(self):
        return self.block_hash.hex()

    def to_block_hash_keeper_call(self):
        return (self.slot, self.block_hash)


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
            elif validator.activation_eligibility_epoch <= block_data.epoch:
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


@dataclass
class OracleProof:
    beaconBlockHash: bytes
    zkProof: bytes

    def to_contract_call(self):
        return (self.beaconBlockHash, self.zkProof)


class ContractsBase:
    lido_locator: LidoLocatorMock
    lido_staking_router: LidoStakingRouterMock
    block_hash_keeper: BeaconBlockHashKeeper
    tvl_contract: ZKTVLOracleContract

    def __init__(self, locator, staiking_router, hash_keeper, tvl_contract):
        self.lido_locator = locator
        self.lido_staking_router = staiking_router
        self.block_hash_keeper = hash_keeper
        self.tvl_contract = tvl_contract

    @property
    def verifier(self):
        raise NotImplementedError("Must be overridden in descendants")

    @property
    def gate_address(self):
        raise NotImplementedError("Must be overridden in descendants")

    def update_block_hash(self, next_beacon_block_hash: BeaconBlockHashRecord, beacon_state: BeaconState):
        new_hash = Balances.get_hash_tree_root(beacon_state.balances)
        # new_hash = next_beacon_block_hash.block_hash
        print(f"Updating block hash to {new_hash.hex()}")
        params = (next_beacon_block_hash.slot, new_hash)
        self.block_hash_keeper.setBeaconBlockHash(params, {})

        block_hash_bytes = to_bytes(self.block_hash_keeper.getBeaconBlockHash(next_beacon_block_hash.slot))
        try:
            assert (to_bytes(block_hash_bytes) == new_hash)
        except AssertionError as e:
            print(f"Contract: {block_hash_bytes.hex()}")
            print(f"Expected: {new_hash.hex()}")
            raise e

    def submit_report(self, report: OracleReport, proof: OracleProof):
        self.tvl_contract.submitReportData(
            report.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION
        )

    def check_if_verifies(self, proof: bytes):
        init_params, column_rotations = [], []
        result = self.verifier.verify(proof, init_params, column_rotations, self.gate_address)
        return result


class MockContracts(ContractsBase):
    _verifier: ZKLLVMVerifierMock
    verification_gate: HexStr

    def __init__(
        self, verifier: ZKLLVMVerifierMock, verification_gate: HexStr, locator, staiking_router, hash_keeper,
        tvl_contract
    ):
        self._verifier = verifier
        self.verification_gate = verification_gate
        super().__init__(locator, staiking_router, hash_keeper, tvl_contract)

    @property
    def verifier(self):
        return self._verifier

    @property
    def gate_address(self):
        return self.verification_gate

    def set_verifier_mock(self, passes=False):
        self.verifier.setPass(passes)

        passes_check = to_bool(self.verifier.verify(b'01' * 32, [], [], self.verification_gate))
        try:
            assert passes_check == passes
        except AssertionError as e:
            print(f"Contract: {passes_check}")
            print(f"Expected: {passes}")


@dataclass
class RealContracts(ContractsBase):
    _verifier: PlaceholderVerifier
    gate: GateArgument

    def __init__(
        self, verifier: PlaceholderVerifier, gate: GateArgument, locator, staiking_router, hash_keeper,
        tvl_contract
    ):
        self._verifier = verifier
        self.verification_gate = gate
        super().__init__(locator, staiking_router, hash_keeper, tvl_contract)

    @property
    def verifier(self):
        return self._verifier

    @property
    def gate_address(self):
        return self.gate.address

    def set_verifier_mock(self, passes=False):
        LOGGER.info({'msg': "set_verifier_mock has no effect on real verifier"})

USE_MOCK = True
Contracts = MockContracts if USE_MOCK else RealContracts

def deploy_contracts(owner, withdrawal_credentials: bytes) -> Contracts:
    deploy_tx_info = {"from": owner}

    staking_router = LidoStakingRouterMock.deploy(withdrawal_credentials, deploy_tx_info)
    locator = LidoLocatorMock.deploy(staking_router.address, deploy_tx_info)
    hash_keeper = BeaconBlockHashKeeper.deploy(deploy_tx_info)

    if USE_MOCK:
        # Mock verifier
        gate_address = HexStr(secrets.token_hex(20))
        verifier = ZKLLVMVerifierMock.deploy(deploy_tx_info)
        tvl_oracle_contract = ZKTVLOracleContract.deploy(
            verifier.address, gate_address, hash_keeper.address, locator.address, deploy_tx_info
        )
        return MockContracts(verifier, gate_address, locator, staking_router, hash_keeper, tvl_oracle_contract)
    else:
        # Real verifier
        verifier_lib = ProofVerifier.deploy(deploy_tx_info)  # used by PlaceholderVerifier
        gate = GateArgument.deploy(deploy_tx_info)
        verifier = PlaceholderVerifier.deploy(deploy_tx_info)
        tvl_oracle_contract = ZKTVLOracleContract.deploy(
            verifier.address, gate.address, hash_keeper.address, locator.address, deploy_tx_info
        )
        return RealContracts(verifier, gate, locator, staking_router, hash_keeper, tvl_oracle_contract)


class BlockHashProvider:
    def gen_block_hashes(self) -> Iterator[BeaconBlockHashRecord]:
        pass


class SyntheticBlockHashProvider(BlockHashProvider):
    def gen_block_hashes(self) -> Iterator[BeaconBlockHashRecord]:
        slot_number = 1
        while True:
            next_hash = secrets.token_bytes(32)
            yield BeaconBlockHashRecord(slot_number, HexBytes(next_hash))
            slot_number += 1


class ConsensusHttpClientBlockHashProvider(BlockHashProvider):
    _final_slot = None
    _starting_slot = None

    BEACON_HEADERS_ENDPOINT = "/eth/v1/beacon/headers/{block_id}"

    def __init__(self, consensus_client_url, start_N_slots_back=30):
        self._base_url = consensus_client_url
        self._start_N_slots_back = start_N_slots_back

    def _init(self):
        block_header_json = self._get_block_header(state_id='head')
        head_slot_number = int(block_header_json["header"]["message"]["slot"])
        self._final_slot = head_slot_number
        self._starting_slot = head_slot_number - self._start_N_slots_back

    def _get_block_header(self, state_id):
        url = self._base_url + self.BEACON_HEADERS_ENDPOINT.format(block_id=state_id)
        with requests.get(url) as response:
            response.raise_for_status()
            json_response = response.json()
            return json_response["data"]

    def gen_block_hashes(self) -> Iterator[BeaconBlockHashRecord]:
        for slot_number in self.slot_range:
            block_header = self._get_block_header(slot_number)
            block_hash = block_header["root"]
            block_hash_bytes = HexBytes(block_hash)
            yield BeaconBlockHashRecord(slot_number, block_hash_bytes)

    @property
    def slot_range(self) -> range:
        if self._final_slot is None:
            self._init()
        return range(self._starting_slot, self._final_slot)


class WithdrawalCredentials:
    LIDO = b'\x01\x02' * 16
    OTHER = b'\xff' * 32


class DI:
    def __init__(self):
        self._contracts = None
        self._server = None
        self._invoker = None

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

    @property
    def oracle_invoker(self) -> OracleInvoker:
        return self._invoker

    @oracle_invoker.setter
    def oracle_invoker(self, value: OracleInvoker):
        self._invoker = value


container = DI()

CONTRACT_VERSION = 1


def main():
    container.server = StubEthApiServer()
    print("Starting server")
    container.server.start_nonblocking()
    print("Server started")

    # this is needed to make brownie with hardforks newer than istanbul
    gas_price('60 gwei')
    sponsor = accounts[1]
    oracle_operator: LocalAccount = accounts.add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    sponsor.transfer(oracle_operator, '10 ether')
    print("Oracle operator balance:", oracle_operator.balance())

    owner = accounts[0]
    print(f"Withdrawal credentials: {WithdrawalCredentials.LIDO.hex()}")

    container.contracts = deploy_contracts(owner, WithdrawalCredentials.LIDO)

    # deployment and  sanity check
    assert to_bytes(container.contracts.lido_staking_router.getWithdrawalCredentials()) == WithdrawalCredentials.LIDO
    assert to_address(
        container.contracts.lido_locator.stakingRouter()
    ) == container.contracts.lido_staking_router.address

    hash_sequence_provider = SyntheticBlockHashProvider()
    # hash_sequence_provider = ConsensusHttpClientBlockHashProvider(os.getenv('CONSENSUS_CLIENT_URI'))
    # print("Hash sequence provider slot range", hash_sequence_provider.slot_range)

    hash_sequence = hash_sequence_provider.gen_block_hashes()

    print("Adding initial state")
    initial_validators = (
            [make_validator(WithdrawalCredentials.LIDO, 0, 1, None) for _ in range(10)] +
            [make_validator(WithdrawalCredentials.OTHER, 0, 1, None) for _ in range(5)]
    )
    initial_balances = [10 * (10 ** 9) for _ in range(10)] + [1000 * (10 ** 9) for _ in range(5)]

    oracle_invoker = OracleInvoker(
        python=os.getenv('ORACLE_PYTHON'),
        cwd=os.getenv('ORACLE_CWD'),
        script=os.getenv('ORACLE_MODULE'),
        env=OracleInvokerEnv(
            bs_api_uri="http://localhost:5000",
            consensus_api_uri="http://localhost:5000",
            execution_api_uri="http://localhost:8545",
            locator_address=container.contracts.lido_locator.address,
            zktvk_contract_address=container.contracts.tvl_contract.address,
        ),
        account=HexStr(oracle_operator.private_key),
        # args=["-d"],
        named_args={"-e": ".env"}
    )
    container.oracle_invoker = oracle_invoker

    block1_meta = next(hash_sequence)
    bs1 = make_beacon_block_state(
        block1_meta.slot, block1_meta.epoch, Constants.Genesis.BLOCK_ROOT, initial_validators, initial_balances
    )
    expected_report1 = OracleReport.compute_expected(block1_meta, WithdrawalCredentials.LIDO, bs1)
    step1_success(block1_meta, bs1, expected_report1)
    input(f"At slot {block1_meta.slot} - press enter to progress")

    block2_meta = next(hash_sequence)
    bs2 = BeaconStateModifier(bs1).set_slot(block2_meta.slot)\
        .update_balance(0, initial_balances[0] + 10 ** 9)\
        .update_balance(7, 10).get()
    step2_fail_verifier_rejects(block2_meta, bs2, expected_report=expected_report1)
    input(f"At slot {block2_meta.slot} - press enter to progress")

    block3_meta = next(hash_sequence)
    bs3 = BeaconStateModifier(bs2).set_slot(block3_meta.slot).modify_validator_fields(0, {"slashed": True}).get()
    step3_fail_wrong_withdrawal_credentials(
        block3_meta, bs3, finalized_slot=block2_meta.slot, expected_report=expected_report1
    )
    input(f"At slot {block3_meta.slot} - press enter to progress")

    block4_meta = next(hash_sequence)
    bs4 = BeaconStateModifier(bs3).set_slot(block4_meta.slot)\
        .update_balance(1, initial_balances[1] + 2 * 10 ** 9)\
        .set_validator_exited(4, block4_meta.epoch).get()

    step4_fail_wrong_beacon_block_hash(block4_meta, bs4, expected_report=expected_report1)

    expected_report4 = OracleReport.compute_expected(block4_meta, WithdrawalCredentials.LIDO, bs4)
    input(f"At slot {block4_meta.slot} - press enter to resubmit with correct hash")
    step4_success(expected_report=expected_report4)
    input(f"At slot {block4_meta.slot} - press enter to progress")

    container.server.terminate()
    print("The End")


def assert_report_matches(actual_report, expected_report):
    try:
        assert actual_report == expected_report
        print(f"Report matches expected:\nExpected: {expected_report}\nActual  : {actual_report}")
    except AssertionError as e:
        print(f"Report does not match:\nExpected: {expected_report}\nActual  : {actual_report}")
        raise e


def assert_report_dont_match(actual_report, unexpected_report):
    try:
        assert actual_report != unexpected_report
    except AssertionError as e:
        print(f"Report matches the unexpected value: {unexpected_report}")
        raise e


def step1_success(block_meta, bs1: BeaconState, expected_report: OracleReport):
    container.server.add_state(
        block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(Constants.Genesis.BLOCK_ROOT), bs1
    )
    container.server.set_chain_pointers(head=block_meta.slot, finalized=block_meta.slot, justified=block_meta.slot)
    container.contracts.update_block_hash(block_meta, bs1)
    container.contracts.set_verifier_mock(passes=True)

    input(f"Ready to run oracle - press enter to start...")
    container.oracle_invoker.run()
    print(f"Oracle run successfully")

    print(f"Checking the report...")
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_matches(latest_report, expected_report)

    return latest_report


def step2_fail_verifier_rejects(block_meta, state: BeaconState, expected_report: OracleReport):
    # this is wrong - should not use HexBytes(block_meta.block_hash) for parent, but I'm making a quick shortcut here
    container.server.add_state(block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(block_meta.block_hash), state)
    container.server.set_chain_pointers(head=block_meta.slot)
    container.contracts.update_block_hash(block_meta, state)
    container.contracts.set_verifier_mock(passes=False)

    report2 = OracleReport(
        block_meta.slot, block_meta.epoch, WithdrawalCredentials.LIDO, 0, 100, Wei(10000)
    )
    proof = OracleProof(block_meta.block_hash, bytes.fromhex("abcdef"))

    try:
        container.contracts.tvl_contract.submitReportData(
            report2.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION
        )
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass

    print(f"Checking the report...")
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_dont_match(latest_report, report2)
    assert_report_matches(latest_report, expected_report)
    print("Report 2 rejected - verifier rejects")


def step3_fail_wrong_withdrawal_credentials(
        block_meta, state: BeaconState, finalized_slot: int, expected_report: OracleReport
):
    # this is wrong - should not use HexBytes(block_meta.block_hash) for parent, but I'm making a quick shortcut here
    container.server.add_state(block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(block_meta.block_hash), state)
    container.server.set_chain_pointers(head=block_meta.slot, finalized=finalized_slot)
    container.contracts.update_block_hash(block_meta, state)
    container.contracts.set_verifier_mock(passes=True)

    report3 = OracleReport(block_meta.slot, block_meta.epoch, WithdrawalCredentials.OTHER, 0, 100, Wei(10000))
    proof = OracleProof(block_meta.block_hash, bytes.fromhex("abcdef"))

    try:
        container.contracts.tvl_contract.submitReportData(
            report3.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION
        )
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass

    print(f"Checking the report...")
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_dont_match(latest_report, report3)
    assert_report_matches(latest_report, expected_report)
    print("Report 3 rejected - wrong invalid credentials")


def step4_fail_wrong_beacon_block_hash(
        block_meta: BeaconBlockHashRecord, state: BeaconState, expected_report: OracleReport
):
    # this is wrong - should not use HexBytes(block_meta.block_hash) for parent, but I'm making a quick shortcut here
    container.server.add_state(block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(block_meta.block_hash), state)
    container.server.set_chain_pointers(head=block_meta.slot, finalized=block_meta.slot, justified=block_meta.slot)

    container.contracts.update_block_hash(block_meta, state)
    container.contracts.set_verifier_mock(passes=True)

    report4 = OracleReport(block_meta.slot, block_meta.epoch, WithdrawalCredentials.LIDO, 0, 100, Wei(10000))
    proof = OracleProof(b'\x00' * 32, bytes.fromhex("abcdef"))
    try:
        container.contracts.submit_report(report4, proof)
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass

    print(f"Checking the report...")
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_dont_match(latest_report, report4)
    assert_report_matches(latest_report, expected_report)
    print("Report 4 rejected - wrong beacon block hash")
    return report4


def step4_success(expected_report: OracleReport):
    print("Resubmitting report4")

    input(f"Ready to run oracle - press enter to start...")
    container.oracle_invoker.run()
    input(f"Oracle run successfully")

    print(f"Checking the report...")
    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_matches(latest_report, expected_report)
    print("Report4 accepted")
