import secrets

import pytest

from brownie import accounts
from brownie import TVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock, BeaconBlockHashKeeper
from eth_typing import HexStr

from dataclasses import dataclass


@dataclass
class Contracts:
    verifier: ZKLLVMVerifierMock
    lido_locator: LidoLocatorMock
    lido_staking_router: LidoStakingRouterMock
    block_hash_keeper: BeaconBlockHashKeeper
    tvl_contract: TVLOracleContract

@pytest.fixture
def owner():
    return accounts[0]

@pytest.fixture
def verification_gate() -> HexStr:
    return HexStr("01234567890123456789")


@pytest.fixture
def withdrawal_credentials() -> bytes:
    return bytes.fromhex("010000000000000000000000b9d7934878b5fb9610b3fe8a5e441e8fad7e293f")


@pytest.fixture
def verifier_mock(owner) -> ZKLLVMVerifierMock:
    return owner.deploy(ZKLLVMVerifierMock)


@pytest.fixture
def staking_router_mock(owner) -> LidoStakingRouterMock:
    return owner.deploy(LidoStakingRouterMock, withdrawal_credentials)


@pytest.fixture
def locator_mock(owner, staking_router) -> LidoLocatorMock:
    return owner.deploy(LidoLocatorMock, staking_router.address)

@pytest.fixture
def beacon_block_hash_keeper(owner):
    return owner.deploy(BeaconBlockHashKeeper)

@pytest.fixture
def tvl_oracle_contract(owner, verifier, hash_keeper, locator, verification_gate):
    owner.deploy(TVLOracleContract, verifier.address, verification_gate, hash_keeper.address, locator.address)

@pytest.fixture
def all_contracts(verifier_mock, locator_mock, staking_router_mock, beacon_block_hash_keeper, tvl_oracle_contract) -> Contracts:
    return Contracts(verifier_mock, locator_mock, staking_router_mock, beacon_block_hash_keeper, tvl_oracle_contract)
