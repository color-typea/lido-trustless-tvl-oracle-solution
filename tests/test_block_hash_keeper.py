import random

import pytest
import secrets
from brownie.convert import to_bytes
from brownie.exceptions import VirtualMachineError


class TestBeaconBlockHashKeeper:

    def test_unknown_slot_reverts(self, beacon_block_hash_keeper):
        with pytest.raises(VirtualMachineError):
            beacon_block_hash_keeper.getBeaconBlockHash(0)

    @pytest.mark.parametrize(
        "slot_number, block_hash",
        [
            (0, b'\x01' + b'\x00' * 31),
            (1, b'\x02' + b'\x00' * 31),
            (2, b'\x00' * 31 + b'\x03'),
            (random.randint(0, 100000000), secrets.token_bytes(32)),
        ]
    )
    def test_get_after_set_with_bytes32(self, beacon_block_hash_keeper, slot_number, block_hash):
        beacon_block_hash_keeper.setBeaconBlockHash((slot_number, block_hash))

        assert to_bytes(beacon_block_hash_keeper.getBeaconBlockHash(slot_number)) == block_hash


    @pytest.mark.parametrize(
        "block_hash", [
            b"\x01" * 10,
            b'\x01' + b'\x00' * 9,
            b'\x01' + b'\x02' * 12,
        ]
    )
    def test_get_after_set_shorter_bytes(self, beacon_block_hash_keeper,  block_hash):
        beacon_block_hash_keeper.setBeaconBlockHash((0, block_hash))
        padding_length = 32 - len(block_hash)
        padding = b'\x00' * padding_length

        assert to_bytes(beacon_block_hash_keeper.getBeaconBlockHash(0)) == (padding + block_hash)

    @pytest.mark.parametrize(
        "bytes_length", [33, 40, 96]
    )
    def test_invalid_hash_value_reverts(self, beacon_block_hash_keeper, bytes_length):
        invalid_block_hash = b'\x01' * bytes_length

        with pytest.raises(OverflowError):
            beacon_block_hash_keeper.setBeaconBlockHash((1, invalid_block_hash))
