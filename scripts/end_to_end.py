from brownie.exceptions import VirtualMachineError
from dataclasses import dataclass
from typing import Iterator

import secrets
import logging

from brownie.network import accounts
from brownie import (
    TVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock,
    BeaconBlockHashKeeper, Wei
)
from brownie.convert import to_bytes, to_address, to_bool, to_int
from eth_typing import HexStr

LOGGER = logging.getLogger("main")

@dataclass
class Contracts:
    verifier: ZKLLVMVerifierMock
    lido_locator: LidoLocatorMock
    lido_staking_router: LidoStakingRouterMock
    block_hash_keeper: BeaconBlockHashKeeper
    tvl_contract: TVLOracleContract


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
class OracleReport:
    slot: int
    epoch: int
    lidoWithdrawalCredentials: bytes
    activeValidators: int
    exitedValidators: int
    totalValueLocked: int

    def to_contract_call(self):
        return (self.slot, self.epoch, self.lidoWithdrawalCredentials, self.activeValidators, self.exitedValidators, self.totalValueLocked)

    @classmethod
    def reconstruct_from_contract(cls, raw_values):
        return cls(
            slot = to_int(raw_values[0]),
            epoch = to_int(raw_values[1]),
            lidoWithdrawalCredentials = to_bytes(raw_values[2]),
            activeValidators = to_int(raw_values[3]),
            exitedValidators = to_int(raw_values[4]),
            totalValueLocked = to_int(raw_values[5]),
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
    tvl_oracle_contract = TVLOracleContract.deploy(verifier.address, verification_gate, hash_keeper.address, locator.address, deploy_tx_info)

    return Contracts(verifier, locator, staking_router, hash_keeper, tvl_oracle_contract)

def gen_block_hashes() -> Iterator[BeaconBlockHashRecord]:
    slot_number = 1
    while True:
        next_hash = secrets.token_bytes(32)
        yield BeaconBlockHashRecord(slot_number, next_hash)
        slot_number += 1


def update_block_hash(next_beacon_block_hash: BeaconBlockHashRecord, beacon_block_hash_keeper: BeaconBlockHashKeeper):
    print(f"Updating block hash for {next_beacon_block_hash}")
    beacon_block_hash_keeper.setBeaconBlockHash(next_beacon_block_hash.to_block_hash_keeper_call(), {})

    block_hash_bytes = to_bytes(beacon_block_hash_keeper.getBeaconBlockHash(next_beacon_block_hash.slot))
    try:
        assert (to_bytes(block_hash_bytes) == next_beacon_block_hash.block_hash)
    except AssertionError as e:
        print(f"Contract: {block_hash_bytes.hex()}")
        print(f"Expected: {next_beacon_block_hash.block_hash.hex()}")
        raise e

def set_verifier_mock(verifier_mock: ZKLLVMVerifierMock, verification_gate: HexStr, passes=False):
    verifier_mock.setPass(passes)

    passes_check = to_bool(verifier_mock.verify(b'01'*32, [], [], verification_gate))
    try:
        assert passes_check == passes
    except AssertionError as e:
        print(f"Contract: {passes_check}")
        print(f"Expected: {passes}")


def main():
    owner = accounts[0]
    oracle_operator = accounts[1]
    print(oracle_operator.address)
    verification_gate = HexStr(secrets.token_hex(20))
    withdrawal_credentials = b'\x01\x02' * 16
    invalid_withdrawal_credentials = b'\x01' * 32
    print(f"Verification gate: {verification_gate}\nWithdrawal credentials: {withdrawal_credentials.hex()}")

    contracts = deploy_contracts(owner, withdrawal_credentials, verification_gate)

    # deployment and  sanity check
    assert to_bytes(contracts.lido_staking_router.getWithdrawalCredentials()) == withdrawal_credentials
    assert to_address(contracts.lido_locator.stakingRouter()) == contracts.lido_staking_router.address

    hash_sequence = gen_block_hashes()
    next_beacon_block_hash = next(hash_sequence)
    update_block_hash(next_beacon_block_hash, contracts.block_hash_keeper)
    set_verifier_mock(contracts.verifier, verification_gate, passes=True)

    report1 = OracleReport(next_beacon_block_hash.slot, next_beacon_block_hash.epoch, withdrawal_credentials, 10, 1, Wei(2 * 10**18))
    proof = OracleProof(next_beacon_block_hash.block_hash, bytes.fromhex("abcdef"))

    contracts.tvl_contract.handleOracleReport(report1.to_contract_call(), proof.to_contract_call())

    latest_report = OracleReport.reconstruct_from_contract(contracts.tvl_contract.getLastReport())
    assert latest_report == report1
    print("Report1 accepted")

    next_beacon_block_hash = next(hash_sequence)
    update_block_hash(next_beacon_block_hash, contracts.block_hash_keeper)
    set_verifier_mock(contracts.verifier, verification_gate, passes=False)

    report2 = OracleReport(
        next_beacon_block_hash.slot, next_beacon_block_hash.epoch, withdrawal_credentials, 0, 100, Wei(10000)
    )
    proof = OracleProof(next_beacon_block_hash.block_hash, bytes.fromhex("abcdef"))

    try:
        contracts.tvl_contract.handleOracleReport(report2.to_contract_call(), proof.to_contract_call())
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass

    latest_report = OracleReport.reconstruct_from_contract(contracts.tvl_contract.getLastReport())
    assert latest_report == report1, "Report was unexpectedly updated"
    print("Success")

    next_beacon_block_hash = next(hash_sequence)
    update_block_hash(next_beacon_block_hash, contracts.block_hash_keeper)
    set_verifier_mock(contracts.verifier, verification_gate, passes=True)

    report3 = OracleReport(
        next_beacon_block_hash.slot, next_beacon_block_hash.epoch, invalid_withdrawal_credentials, 0, 100, Wei(10000)
    )
    proof = OracleProof(next_beacon_block_hash.block_hash, bytes.fromhex("abcdef"))

    try:
        contracts.tvl_contract.handleOracleReport(report3.to_contract_call(), proof.to_contract_call())
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass

    latest_report = OracleReport.reconstruct_from_contract(contracts.tvl_contract.getLastReport())
    assert latest_report == report1, "Report was unexpectedly updated"

    report4 = OracleReport(
        next_beacon_block_hash.slot, next_beacon_block_hash.epoch, withdrawal_credentials, 0, 100, Wei(10000)
    )
    invalid_block_hash = b'\x00'*32
    proof = OracleProof(invalid_block_hash, bytes.fromhex("abcdef"))

    try:
        contracts.tvl_contract.handleOracleReport(report4.to_contract_call(), proof.to_contract_call())
        assert False, "Report should have been rejected"
    except VirtualMachineError:
        pass

    latest_report = OracleReport.reconstruct_from_contract(contracts.tvl_contract.getLastReport())
    assert latest_report == report1, "Report was unexpectedly updated"

    proof = OracleProof(next_beacon_block_hash.block_hash, bytes.fromhex("abcdef"))
    contracts.tvl_contract.handleOracleReport(report4.to_contract_call(), proof.to_contract_call())
    latest_report = OracleReport.reconstruct_from_contract(contracts.tvl_contract.getLastReport())
    assert latest_report == report4
    print("Report4 accepted")

    print("Success")