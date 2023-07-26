
import os

from brownie.exceptions import VirtualMachineError
from brownie.network.account import LocalAccount
from dataclasses import dataclass
import logging

from brownie.network import accounts
from brownie import (
    ZKTVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock,
    BeaconBlockHashKeeper, Wei,
    GateArgument, Gate0, Gate4, CircuitParams
)
from brownie import (ProofVerifier, PlaceholderVerifier)
from brownie.network import gas_price

from brownie.convert import to_bytes, to_address, to_bool, to_int
from eth_typing import HexStr

import secrets
from hexbytes import HexBytes

from scripts.components.block_hash_provider import BeaconBlockHashRecord, SyntheticBlockHashProvider
from scripts.components.oracle import OracleReport, OracleProof, WithdrawalCredentials, BeaconStateSummary
from scripts.components.utils import Printer, with_timing
from scripts.components.oracle_invoker import OracleInvoker, OracleInvokerEnv
from scripts.components.eth_node_api_stub_server import StubEthApiServer
from scripts.components.eth_consensus_layer_ssz import BeaconState, Balances, BeaconStateModifier
from scripts.components.eth_ssz_utils import make_validator, make_beacon_block_state, Constants

CURDIR = os.path.dirname(__file__)
LOGGER = logging.getLogger("main")
CONTRACT_VERSION = 1
USE_MOCK = False

printer = Printer()

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
        # print(f"Updating balances hash to {new_hash.hex()}")
        params = (next_beacon_block_hash.slot, new_hash)
        self.block_hash_keeper.setBeaconBlockHash(params, {})

        block_hash_bytes = to_bytes(self.block_hash_keeper.getBeaconBlockHash(next_beacon_block_hash.slot))
        try:
            assert (to_bytes(block_hash_bytes) == new_hash)
        except AssertionError as e:
            printer.error("Failed to update bock hash")
            printer.detail(f"Contract: {block_hash_bytes.hex()}")
            printer.detail(f"Expected: {new_hash.hex()}")
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
            printer.error("Failed to set verifier mock")
            printer.detail(f"Contract: {passes_check}")
            printer.detail(f"Expected: {passes}")


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
        gate0 = Gate0.deploy(deploy_tx_info)
        gate4 = Gate4.deploy(deploy_tx_info)
        circuit_params = CircuitParams.deploy(deploy_tx_info)
        gate = GateArgument.deploy(deploy_tx_info)
        verifier = PlaceholderVerifier.deploy(deploy_tx_info)
        tvl_oracle_contract = ZKTVLOracleContract.deploy(
            verifier.address, gate.address, hash_keeper.address, locator.address, deploy_tx_info
        )
        return RealContracts(verifier, gate, locator, staking_router, hash_keeper, tvl_oracle_contract)


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

def main():
    server = StubEthApiServer()
    print("Starting server")
    server.start_nonblocking()
    print("Server started")
    try:
        _run_with_server(server)
    finally:
        server.terminate()

def _run_with_server(server):
    container.server = server
    # this is needed to make brownie with hardforks newer than istanbul
    gas_price('60 gwei')
    sponsor = accounts[1]
    oracle_operator: LocalAccount = accounts.add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    sponsor.transfer(oracle_operator, '10 ether')
    # printer.info(f"Oracle operator balance: {oracle_operator.balance()}")

    owner = accounts[0]
    # printer.info(f"Withdrawal credentials: {WithdrawalCredentials.LIDO.hex()}")

    printer.wait("Deploying contracts - press enter to continue")
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

    initial_validators = (
            [make_validator(WithdrawalCredentials.LIDO, 0, 1, None) for _ in range(5)] +
            [make_validator(WithdrawalCredentials.OTHER, 0, 1, None) for _ in range(5)]
    )
    initial_balances = [10 * (10 ** 9) for _ in range(5)] + [1000 * (10 ** 9) for _ in range(5)]

    container.oracle_invoker = OracleInvoker(
        python=os.getenv('ORACLE_PYTHON'),
        cwd=os.getenv('ORACLE_CWD'),
        script=os.getenv('ORACLE_MODULE'),
        env=OracleInvokerEnv(
            bs_api_uri="http://localhost:5000",
            consensus_api_uri="http://localhost:5000",
            execution_api_uri="http://localhost:8545",
            locator_address=container.contracts.lido_locator.address,
            zktvk_contract_address=container.contracts.tvl_contract.address,
            log_level="WARN"
        ),
        account=HexStr(oracle_operator.private_key),
        # args=["-d"],
        named_args={"-e": ".env"}
    )
    # oracle_invoker.print_env_and_command()
    # input("Printed oracle invocation command - press enter to continue")

    printer.info(f"TVL Oracle contract address {container.contracts.tvl_contract.address}")
    printer.wait("Press enter to continue")

    block1_meta = next(hash_sequence)
    bs1 = make_beacon_block_state(
        block1_meta.slot, block1_meta.epoch, Constants.Genesis.BLOCK_ROOT, initial_validators, initial_balances
    )
    expected_report1 = OracleReport.compute_expected(block1_meta, WithdrawalCredentials.LIDO, bs1)
    printer.header("======== Step 1 - run oracle, report accepted ========")
    state_summary1 = BeaconStateSummary.compute("step1", block1_meta, bs1)
    printer.info(state_summary1)
    step1_success(block1_meta, bs1, expected_report1)
    printer.header("======== End Step 1 - run oracle, report accepted ========")
    printer.wait(f"Press enter to progress")

    printer.header("======== Step 2 - fake report, fails proof verification check ========")
    block2_meta = next(hash_sequence)
    bs2 = BeaconStateModifier(bs1).set_slot(block2_meta.slot)\
        .update_balance(0, initial_balances[0] + 10 ** 9)\
        .update_balance(7, 10 ** 9).get()
    state_summary2 = BeaconStateSummary.compute("step2", block2_meta, bs2)
    # state_summary2.print_difference(state_summary1)
    step2_fail_verifier_rejects(block2_meta, bs2, expected_report=expected_report1)
    printer.header("======== End step 2 - fake report, fails proof verification check ========")
    printer.wait(f"Press enter to progress")

    printer.header("======== Step 3 - fake report fails withdrawal credentials check ========")
    block3_meta = next(hash_sequence)
    bs3 = BeaconStateModifier(bs2).set_slot(block3_meta.slot).modify_validator_fields(0, {"slashed": True}).get()
    # state_summary3 = BeaconStateSummary.compute("step3", block3_meta, bs3)
    # state_summary3.print_difference(state_summary2)
    step3_fail_wrong_withdrawal_credentials(
        block3_meta, bs3, finalized_slot=block2_meta.slot, expected_report=expected_report1
    )
    printer.header("======== End step 3 - fake report fails withdrawal credentials check ========")
    printer.wait(f"Press enter to progress")

    printer.header("======== Step 4.1 - fake report  fails balance hash check ========")
    block4_meta = next(hash_sequence)
    bs4 = BeaconStateModifier(bs3).set_slot(block4_meta.slot)\
        .update_balance(1, initial_balances[1] + 2 * 10 ** 9)\
        .set_validator_exited(4, block4_meta.epoch).get()
    state_summary4 = BeaconStateSummary.compute("step4", block4_meta, bs4)
    # state_summary4.print_difference(state_summary3)

    step4_fail_wrong_balances_hash(block4_meta, bs4, expected_report=expected_report1)
    printer.header("======== End Step 4.1 - fake report fails balance hash check ========")
    printer.wait(f"Press enter to progress")

    printer.header("======== Step 4.2 - run oracle, report accepted ========")
    expected_report4 = OracleReport.compute_expected(block4_meta, WithdrawalCredentials.LIDO, bs4)
    printer.detail(str(state_summary4))
    state_summary4.print_difference(state_summary1, printer)
    step4_success(expected_report=expected_report4)
    printer.header("======== End step 4.2 - run oracle, report accepted ========")
    printer.wait(f"Press enter to finish")
    printer.success("The End")


def assert_report_matches(actual_report, expected_report, suppress_print=False):
    if not suppress_print:
        printer.info(f"Checking the report stored in the contract...")
    try:
        assert actual_report == expected_report
        # print("Check succeeded")
        if not suppress_print:
            printer.success(f"Report matches expected")
            printer.detail(f"Expected: {expected_report}")
            printer.detail(f"Actual  : {actual_report}")
    except AssertionError as e:
        printer.error(f"Report does not match:")
        printer.detail(f"Expected: {expected_report}\nActual  : {actual_report}")
        raise e


def assert_report_dont_match(actual_report, unexpected_report):
    try:
        assert actual_report != unexpected_report
    except AssertionError as e:
        printer.error(f"Report matches the unexpected value: {unexpected_report}")
        raise e


def step1_success(block_meta, bs1: BeaconState, expected_report: OracleReport):
    container.server.add_state(
        block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(Constants.Genesis.BLOCK_ROOT), bs1
    )
    container.server.set_chain_pointers(head=block_meta.slot, finalized=block_meta.slot, justified=block_meta.slot)
    container.contracts.update_block_hash(block_meta, bs1)
    container.contracts.set_verifier_mock(passes=True)

    printer.wait(f"Ready to run oracle - press enter to start...")
    printer.info(f"Running oracle - this should take a few seconds")
    with with_timing(printer, "Run oracle"):
        container.oracle_invoker.run()
    printer.success(f"Oracle run successful, report accepted, proof verifies")

    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_matches(latest_report, expected_report)

    return latest_report


def step2_fail_verifier_rejects(block_meta, state: BeaconState, expected_report: OracleReport):
    # this should use previous block state hash for parent, but it doesn't affect the report, verifier or contract, so
    # I'm making a quick shortcut here
    container.server.add_state(block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(block_meta.block_hash), state)
    container.server.set_chain_pointers(head=block_meta.slot)
    container.contracts.update_block_hash(block_meta, state)
    container.contracts.set_verifier_mock(passes=False)

    report2 = OracleReport(
        block_meta.slot, block_meta.epoch, WithdrawalCredentials.LIDO, 0, 100, Wei(10000)
    )
    proof = OracleProof(Balances.get_hash_tree_root(state.balances), bytes.fromhex("abcdef") * 1000)

    try:
        printer.info("Submitting fake Report2 with incorrect ZK-proof")
        container.contracts.tvl_contract.submitReportData(
            report2.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION
        )
        assert False, "Report2 should have been rejected"
    except VirtualMachineError:
        printer.expected_fail("Report2 expectedly rejected")
        pass

    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_dont_match(latest_report, report2)
    assert_report_matches(latest_report, expected_report, suppress_print=True)


def step3_fail_wrong_withdrawal_credentials(
        block_meta, state: BeaconState, finalized_slot: int, expected_report: OracleReport
):
    # this should use previous block state hash for parent, but it doesn't affect the report, verifier or contract, so
    # I'm making a quick shortcut here
    container.server.add_state(block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(block_meta.block_hash), state)
    container.server.set_chain_pointers(head=block_meta.slot, finalized=finalized_slot)
    container.contracts.update_block_hash(block_meta, state)
    container.contracts.set_verifier_mock(passes=True)

    report3 = OracleReport(block_meta.slot, block_meta.epoch, WithdrawalCredentials.OTHER, 0, 100, Wei(10000))
    proof = OracleProof(Balances.get_hash_tree_root(state.balances), bytes.fromhex("abcdef"))

    try:
        printer.info(f"Submitting fake Report3 with incorrect Withdrawal credentials")
        printer.detail(
              f"Expected  :{WithdrawalCredentials.LIDO.hex()}\n"
              f"Submitting:{report3.lidoWithdrawalCredentials.hex()}"
        )
        container.contracts.tvl_contract.submitReportData(
            report3.to_contract_call(), proof.to_contract_call(), CONTRACT_VERSION
        )
        assert False, "Report3 should have been rejected"
    except VirtualMachineError:
        printer.expected_fail("Report3 expectedly rejected")
        pass

    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_dont_match(latest_report, report3)
    assert_report_matches(latest_report, expected_report, suppress_print=True)


def step4_fail_wrong_balances_hash(
        block_meta: BeaconBlockHashRecord, state: BeaconState, expected_report: OracleReport
):
    # this should use previous block state hash for parent, but it doesn't affect the report, verifier or contract, so
    # I'm making a quick shortcut here
    container.server.add_state(block_meta.slot, HexBytes(block_meta.block_hash), HexBytes(block_meta.block_hash), state)
    container.server.set_chain_pointers(head=block_meta.slot, finalized=block_meta.slot, justified=block_meta.slot)

    container.contracts.update_block_hash(block_meta, state)
    container.contracts.set_verifier_mock(passes=True)

    with open(os.path.join(CURDIR, "proof.hex"), "r") as proof_bin_hex:
        proof_hex = proof_bin_hex.read()
        proof = bytes.fromhex(proof_hex[2:])

    report4 = OracleReport(block_meta.slot, block_meta.epoch, WithdrawalCredentials.LIDO, 0, 100, Wei(10000))
    proof = OracleProof(b'\x00' * 32, proof)
    try:
        printer.info(f"Submitting fake Report4 with incorrect balances merkle hash")
        printer.detail(
            f"Expected  :{Balances.get_hash_tree_root(state.balances).hex()}\n"
            f"Submitting:{proof.beaconBlockHash.hex()}"
        )
        container.contracts.submit_report(report4, proof)
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        printer.expected_fail("Report4 expectedly rejected")
        pass

    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_dont_match(latest_report, report4)
    assert_report_matches(latest_report, expected_report, suppress_print=True)
    return report4


def step4_success(expected_report: OracleReport):
    printer.wait(f"Ready to run oracle - press enter to start...")
    printer.info(f"Running oracle - this should take a few seconds")
    with with_timing(printer, "Run oracle"):
        container.oracle_invoker.run()
    printer.success(f"Oracle run successful, report accepted, proof verifies")

    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_matches(latest_report, expected_report)
