import secrets
from typing import Iterator

import requests
from hexbytes import HexBytes
from dataclasses import dataclass

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
