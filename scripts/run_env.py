import dataclasses

from brownie.network import accounts
from brownie.network.account import LocalAccount
from brownie import (
    ZKTVLOracleContract, LidoLocatorMock, LidoStakingRouterMock, ZKLLVMVerifierMock,
    BeaconBlockHashKeeper, Wei,
    GateArgument, Gate0, Gate6, CircuitParams
)
from brownie import (ProofVerifier, PlaceholderVerifier)
from brownie.network import gas_price

from scripts.components.oracle import WithdrawalCredentials
from scripts.components.utils import Printer

@dataclasses.dataclass
class Contracts:
    verifier: PlaceholderVerifier
    gate: GateArgument
    lido_locator: LidoLocatorMock
    lido_staking_router: LidoStakingRouterMock
    block_hash_keeper: BeaconBlockHashKeeper
    tvl_contract: ZKTVLOracleContract

def deploy_contracts(owner, withdrawal_credentials: bytes) -> Contracts:
    deploy_tx_info = {"from": owner}

    staking_router = LidoStakingRouterMock.deploy(withdrawal_credentials, deploy_tx_info)
    locator = LidoLocatorMock.deploy(staking_router.address, deploy_tx_info)
    hash_keeper = BeaconBlockHashKeeper.deploy(deploy_tx_info)

    # Real verifier
    verifier_lib = ProofVerifier.deploy(deploy_tx_info)  # used by PlaceholderVerifier
    gate0 = Gate0.deploy(deploy_tx_info)
    gate6 = Gate6.deploy(deploy_tx_info)
    circuit_params = CircuitParams.deploy(deploy_tx_info)
    gate = GateArgument.deploy(deploy_tx_info)
    verifier = PlaceholderVerifier.deploy(deploy_tx_info)
    tvl_oracle_contract = ZKTVLOracleContract.deploy(
        verifier.address, gate.address, hash_keeper.address, locator.address, deploy_tx_info
    )
    return Contracts(verifier, gate, locator, staking_router, hash_keeper, tvl_oracle_contract)

printer = Printer()

def main():
    # this is needed to make brownie with hardforks newer than istanbul
    gas_price('60 gwei')
    sponsor = accounts[1]
    oracle_operator: LocalAccount = accounts.add("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    sponsor.transfer(oracle_operator, '10 ether')
    # printer.info(f"Oracle operator balance: {oracle_operator.balance()}")

    owner = accounts[0]
    # printer.info(f"Withdrawal credentials: {WithdrawalCredentials.LIDO.hex()}")

    contracts = deploy_contracts(owner, WithdrawalCredentials.LIDO)
    printer.header("ZKTVLContract address")
    printer.info(contracts.tvl_contract.address)

    version = contracts.tvl_contract.getContractVersion()
    printer.info(f"Contract version {version}")
    printer.wait("Running env - press any key to stop")


