from dataclasses import dataclass
from http import HTTPStatus
from typing import BinaryIO

import requests
from hexbytes import HexBytes
from io import BytesIO

from scripts.components.eth_consensus_layer_ssz import BeaconState


@dataclass
class BeaconBlockHashRecord:
    slot: int
    block_hash: HexBytes
    parent_hash: HexBytes

    @property
    def epoch(self):
        return self.slot // 32

    def hash_str(self):
        return self.block_hash.hex()

    def to_block_hash_keeper_call(self):
        return (self.slot, self.block_hash)


class ConsensusClient:
    BEACON_HEADERS_ENDPOINT = "/eth/v1/beacon/headers/{block_id}"
    def __init__(self, consensus_client_url):
        self._base_url = consensus_client_url

    def _get_block_header_raw(self, state_id):
        url = self._base_url + self.BEACON_HEADERS_ENDPOINT.format(block_id=state_id)
        with requests.get(url) as response:
            response.raise_for_status()
            json_response = response.json()
            return json_response["data"]

    def get_block_header(self, state_id) -> BeaconBlockHashRecord:
        raw = self._get_block_header_raw(state_id)
        message = raw["header"]["message"]
        return BeaconBlockHashRecord(
            slot = int(message["slot"]),
            block_hash = HexBytes(raw["root"]),
            parent_hash = HexBytes(message["parent_root"])
        )

class PreloadedBeaconStateLoader:
    def __init__(self, bs_path):
        self.bs_path = bs_path
    def load_beacon_state(self, _state_id) -> bytes:
        with open(self.bs_path, "rb") as bs_file:
            return bs_file.read()

class BeaconStateLoader:
    ENDPOINT = "eth/v2/debug/beacon/states/{state_id}"
    def __init__(self, beacon_api_url):
        self._base_url = beacon_api_url

    def load_beacon_state(self, state_id) -> bytes:
        complete_endpoint = self._base_url + self.ENDPOINT.format(state_id=state_id)
        headers = {"Accept": "application/octet-stream"}
        with requests.get(complete_endpoint, headers=headers) as response:
            response.raise_for_status()

            return response.content
