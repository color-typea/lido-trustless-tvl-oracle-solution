import secrets
from hexbytes import HexBytes

from typing import Iterator, Tuple

from eth_node_api_stub_server import StubEthApiServer
from eth_consensus_layer_ssz import BeaconStateModifier
from eth_ssz_utils import make_validator, make_beacon_block_state, Constants


def gen_block_hashes() -> Iterator[Tuple[int, bytes]]:
    slot_number = 1
    while True:
        next_hash = secrets.token_bytes(32)
        yield slot_number, next_hash
        slot_number += 1


class WithdrawalCredentials:
    LIDO =b"\x01" + b"\x00" * 15 + b"\x01\x02\x03\x04" * 4
    OTHER = b"\x00\x01" * 16


def main():
    hash_sequence = gen_block_hashes()

    server = StubEthApiServer()
    print("Starting server")
    server.start_nonblocking()
    print("Server started")

    print("Adding initial state")
    initial_validators = (
            [make_validator(WithdrawalCredentials.LIDO, 0, 1, None) for _ in range(10)] +
            [make_validator(WithdrawalCredentials.OTHER, 0, 1, None) for _ in range(5)]
    )
    initial_balances = [(idx + 1) * (10 ** 9) for idx in range(len(initial_validators))]

    slot, beacon_block_hash = next(hash_sequence)
    bs1 = make_beacon_block_state(
        slot, slot // 32, Constants.Genesis.BLOCK_ROOT, initial_validators, initial_balances
    )

    server.add_state(slot, HexBytes(beacon_block_hash), HexBytes(Constants.Genesis.BLOCK_ROOT), bs1)
    server.set_chain_pointers(head=slot, finalized=slot, justified=slot)
    input(f"At slot {slot} - press any key to progress")

    slot, beacon_block_hash = next(hash_sequence)
    bs2 = BeaconStateModifier(bs1).update_balance(0, 1234567890).update_balance(7, 10).get()
    server.add_state(slot, HexBytes(beacon_block_hash), HexBytes(beacon_block_hash), bs2)
    server.set_chain_pointers(head=slot)
    input(f"At slot {slot} - press any key to progress")

    slot, beacon_block_hash = next(hash_sequence)
    bs3 = BeaconStateModifier(bs2).modify_validator_fields(0, {"slashed": True}).get()
    server.add_state(slot, beacon_block_hash, bs3)
    server.set_chain_pointers(head=slot, finalized=slot - 1)
    input(f"At slot {slot} - press any key to progress")

    input("The End")


if __name__ == "__main__":
    main()
