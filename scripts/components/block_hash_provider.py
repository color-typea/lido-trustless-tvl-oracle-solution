import secrets
from typing import Iterator

from hexbytes import HexBytes

from scripts.components.concensus_client import BeaconBlockHashRecord
from scripts.components.concensus_client import ConsensusClient


class BlockHashProvider:
    def gen_block_hashes(self) -> Iterator[BeaconBlockHashRecord]:
        pass


class SyntheticBlockHashProvider(BlockHashProvider):
    def gen_block_hashes(self) -> Iterator[BeaconBlockHashRecord]:
        slot_number = 1
        parent_hash = secrets.token_bytes(32)
        while True:
            next_hash = secrets.token_bytes(32)
            yield BeaconBlockHashRecord(slot_number, block_hash=HexBytes(next_hash), parent_hash=parent_hash)
            parent_hash = next_hash
            slot_number += 1


class ConsensusHttpClientBlockHashProvider(BlockHashProvider):
    _final_slot = None
    _starting_slot = None

    def __init__(self, consensus_client_url, start_N_slots_back=30):
        self._cc = ConsensusClient(consensus_client_url)
        self._start_N_slots_back = start_N_slots_back

    def _init(self):
        block_header_json = self._cc.get_block_header(state_id='head')
        head_slot_number = int(block_header_json["header"]["message"]["slot"])
        self._final_slot = head_slot_number
        self._starting_slot = head_slot_number - self._start_N_slots_back


    def gen_block_hashes(self) -> Iterator[BeaconBlockHashRecord]:
        for slot_number in self.slot_range:
            yield self._cc.get_block_header(slot_number)

    @property
    def slot_range(self) -> range:
        if self._final_slot is None:
            self._init()
        return range(self._starting_slot, self._final_slot)