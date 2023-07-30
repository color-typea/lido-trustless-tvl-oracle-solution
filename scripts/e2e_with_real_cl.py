import os

from brownie.network.account import LocalAccount
from dataclasses import dataclass
import logging

from brownie.network import accounts
from brownie import (
    ZKTVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock,
    BeaconBlockHashKeeper, Wei,
    GateArgument, Gate0, Gate6, CircuitParams
)
from brownie import (ProofVerifier, PlaceholderVerifier)
from brownie.network import gas_price

from brownie.convert import to_bytes, to_address, to_bool, to_int
from eth_typing import HexStr

from scripts.components.eth_ssz_utils import Constants, make_beacon_block_state, make_validator
from scripts.components.concensus_client import (
    BeaconStateLoader, BeaconBlockHashRecord, ConsensusClient,
    PreloadedBeaconStateLoader
)
from scripts.components.oracle import OracleReport, OracleProof, WithdrawalCredentials
from scripts.components.utils import Printer, with_timing
from scripts.components.oracle_invoker import OracleInvoker, OracleInvokerEnv
from scripts.components.eth_node_api_stub_server import StubEthApiServer
from scripts.components.eth_consensus_layer_ssz import BeaconState, Balances

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


@dataclass
class Contracts(ContractsBase):
    _verifier: PlaceholderVerifier
    gate: GateArgument

    def __init__(
            self, verifier: PlaceholderVerifier, gate: GateArgument, locator, staiking_router, hash_keeper,
            tvl_contract
    ):
        self.lido_locator = locator
        self.lido_staking_router = staiking_router
        self.block_hash_keeper = hash_keeper
        self.tvl_contract = tvl_contract

        self._verifier = verifier
        self.verification_gate = gate
        super().__init__(locator, staiking_router, hash_keeper, tvl_contract)

    @property
    def verifier(self):
        return self._verifier

    @property
    def gate_address(self):
        return self.gate.address

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

    @classmethod
    def deploy(cls, owner, withdrawal_credentials: bytes) -> 'Contracts':
        deploy_tx_info = {"from": owner}

        staking_router = LidoStakingRouterMock.deploy(withdrawal_credentials, deploy_tx_info)
        locator = LidoLocatorMock.deploy(staking_router.address, deploy_tx_info)
        hash_keeper = BeaconBlockHashKeeper.deploy(deploy_tx_info)

        # Real verifier
        verifier_lib = ProofVerifier.deploy(deploy_tx_info)  # used by PlaceholderVerifier
        gate0 = Gate0.deploy(deploy_tx_info)
        gate4 = Gate6.deploy(deploy_tx_info)
        circuit_params = CircuitParams.deploy(deploy_tx_info)
        gate = GateArgument.deploy(deploy_tx_info)
        verifier = PlaceholderVerifier.deploy(deploy_tx_info)
        tvl_oracle_contract = ZKTVLOracleContract.deploy(
            verifier.address, gate.address, hash_keeper.address, locator.address, deploy_tx_info
        )
        return cls(verifier, gate, locator, staking_router, hash_keeper, tvl_oracle_contract)


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

    # printer.wait("Deploying contracts - press enter to continue")
    container.contracts = Contracts.deploy(owner, WithdrawalCredentials.LIDO)

    # deployment and  sanity check
    assert to_bytes(container.contracts.lido_staking_router.getWithdrawalCredentials()) == WithdrawalCredentials.LIDO
    assert to_address(
        container.contracts.lido_locator.stakingRouter()
    ) == container.contracts.lido_staking_router.address

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

    # printer.info(f"TVL Oracle contract address {container.contracts.tvl_contract.address}")
    # printer.wait("Press enter to continue")
    cc = ConsensusClient(os.getenv('CONSENSUS_CLIENT_URI'))
    bsc = PreloadedBeaconStateLoader("/home/john/Projects/crypto/lido/playground-node/ssz/6983968.ssz")
    # bsc = BeaconStateLoader(os.getenv('BEACON_STATE_CLIENT_URI'))

    printer.header("Reading Beacon chain slot pointers (latest, finalized and justified)")
    printer.detail("This operation is part of the script setup, and will not happen in actual oracle operations")
    with with_timing(printer, "Reading Beacon chain pointers"):
        finalized_slot = cc.get_block_header('finalized')
        # Public API serving debug endpoint sometimes lag one epoch behind
        # target_finalized_slot_number = (finalized_slot.epoch - 1) * 32
        # ref_slot = 6983999 + 1
        ref_slot = 6983968
        target_slot = cc.get_block_header(ref_slot)
        justified_slot = cc.get_block_header('justified')
        head_slot = cc.get_block_header('head')
        printer.info(f"Head: {head_slot.slot}, finalized: {finalized_slot.slot}, frameRefSlot: {target_slot.slot}")
    
    printer.header("Pulling Beacon State")
    printer.detail("This operation is part of the script setup, and will not happen in actual oracle operations")
    with with_timing(printer, "Pulling Beacon chain state into the script"):
        finalized_beacon_state_bytes = bsc.load_beacon_state(target_slot.slot)

    printer.header("Parsing Beacon State")
    printer.detail("This operation is part of the script setup, and will not happen in actual oracle operations")
    with with_timing(printer, "Parsing Beacon state SSZ"):
        finalized_beacon_state = BeaconState.from_ssz(finalized_beacon_state_bytes)

    container.server.add_state(
        target_slot.slot, target_slot.block_hash, target_slot.parent_hash, finalized_beacon_state
    )
    container.server.set_chain_pointers(
        head=head_slot.slot, finalized=target_slot.slot, justified=justified_slot.slot
    )
    container.contracts.update_block_hash(target_slot, finalized_beacon_state)

    expected_report = OracleReport.compute_expected(target_slot, WithdrawalCredentials.LIDO, finalized_beacon_state)
    printer.header("======== Step 1 - run oracle, report accepted ========")
    step1_success(target_slot, finalized_beacon_state, expected_report)
    printer.header("======== End Step 1 - run oracle, report accepted ========")


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
    # printer.wait(f"Ready to run oracle - press enter to start...")
    printer.info(f"Running oracle - this should take a some time")
    with with_timing(printer, "Run oracle"):
        container.oracle_invoker.run()
    printer.success(f"Oracle run successful, report accepted, proof verifies")

    latest_report = OracleReport.reconstruct_from_contract(container.contracts.tvl_contract.getLastReport())
    assert_report_matches(latest_report, expected_report)

    return latest_report
