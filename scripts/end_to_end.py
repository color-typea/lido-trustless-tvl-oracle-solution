from dataclasses import dataclass
from typing import Iterator

import secrets
import logging

from brownie.network import accounts
from brownie import TVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock, BeaconBlockHashKeeper
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

    def hash_str(self):
        return self.block_hash.hex()

    def to_block_hash_keeper_call(self):
        return (self.slot, self.block_hash)

def deploy_contracts(owner, withdrawal_credentials: bytes, verification_gate: HexStr) -> Contracts:
    deploy_tx_info = {"from": owner}
    verifier = ZKLLVMVerifierMock.deploy(deploy_tx_info)
    staking_router = LidoStakingRouterMock.deploy(withdrawal_credentials, deploy_tx_info)
    locator = LidoLocatorMock.deploy(staking_router.address, deploy_tx_info)
    hash_keeper = BeaconBlockHashKeeper.deploy(deploy_tx_info)
    tvl_oracle_contract = TVLOracleContract.deploy(verifier.address, verification_gate, hash_keeper.address, locator.address, deploy_tx_info)

    return Contracts(verifier, locator, staking_router, hash_keeper, tvl_oracle_contract)

def gen_block_hashes() -> Iterator[BeaconBlockHashRecord]:
    slot_number = 0
    while True:
        next_hash = secrets.token_bytes(32)
        yield BeaconBlockHashRecord(slot_number, next_hash)
        slot_number += 1


def main():
    cairo_bin_dir = ""

    owner = accounts[0]
    oracle_operator = accounts[1]
    print(oracle_operator.address)
    verification_gate = HexStr(secrets.token_hex(20))
    withdrawal_credentials = secrets.token_bytes(32)
    print(f"Verification gate: {verification_gate}\nWithdrawal credentials: {withdrawal_credentials.hex()}")

    contracts = deploy_contracts(owner, withdrawal_credentials, verification_gate)

    hash_sequence = gen_block_hashes()
    next_beacon_block_hash = next(hash_sequence)

    contracts.block_hash_keeper.setBeaconBlockHash(next_beacon_block_hash.to_block_hash_keeper_call(), {})

    block_hash = contracts.block_hash_keeper.getBeaconBlockHash(next_beacon_block_hash.slot)
    print(type(block_hash))
    assert(block_hash == next_beacon_block_hash.block_hash)