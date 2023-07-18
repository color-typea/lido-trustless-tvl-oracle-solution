import io

import dataclasses

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

import ssz
from hexbytes import HexBytes
from ssz.hashable_list import HashableList
from ssz.hashable_vector import HashableVector
from typing import Optional

import json

import threading
from flask import Flask, jsonify, send_file, request

from scripts.components.eth_consensus_layer_ssz import BeaconState, EnhancedHashableContainer, BeaconBlockHeader

LOGGER = logging.getLogger(__name__)

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, EnhancedHashableContainer):
            return obj.as_dict()
        if isinstance(obj, (bytes, HexBytes)):
            return obj.hex()
        if isinstance(obj, (HashableVector, HashableList)):
            return obj.elements.tolist()
        return super().default(obj)


class ServerThread(threading.Thread):
    def __init__(self, app, host, port):
        from werkzeug.serving import make_server
        self.server_address = f"{host}:{port}"
        super().__init__()
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        LOGGER.info('starting server at %s', self.server_address)
        print(f'starting server at {self.server_address}')
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


@dataclasses.dataclass
class BeaconBlock:
    slot: int
    root: HexBytes
    parent_root: HexBytes
    state: BeaconState

class StubEthApiServer:
    LOGGER = logging.getLogger(__name__ + ".StubEthApiServer")
    def __init__(self):
        self.app = Flask(__name__)

        self.states = {
            'head': 0,
            'finalized': 0,
            'justified': 0
        }
        self._beacon_blocks = dict()

        self._init_routes()

    def _init_routes(self):
        self.app.json_encoder = JsonEncoder
        self.app.route('/eth/v1/beacon/headers/<state_id>', methods=['GET'])(self.get_header)
        self.app.route('/eth/v1/beacon/blocks/<state_id>/root', methods=['GET'])(self.get_beacon_root)
        self.app.route('/eth/v2/beacon/blocks/<state_id>', methods=['GET'])(self.get_beacon_block)
        self.app.route('/eth/v2/debug/beacon/states/<state_id>', methods=['GET'])(self.get_beacon_state)

    def _find_block_for_state(self, state_id) -> BeaconBlock:
        if state_id in self.states:
            slot_number =  self.states[state_id]
            return self._beacon_blocks[slot_number]
        elif state_id.startswith("0x"):
            return self._find_block(HexBytes(state_id))
        else:
            slot_number = int(state_id)
            return self._beacon_blocks[slot_number]

    def _find_block(self, root: HexBytes):
        for _slot, block in self._beacon_blocks.items():  # for name, age in dictionary.iteritems():  (for Python 2.x)
            if block.root == root:
                return block
        return None

    def get_header(self, state_id = None):
        state_id = state_id if state_id else request.args.get('slot')

        block = self._find_block_for_state(state_id)
        response = {
            "execution_optimistic": False,
            "finalized": self.states["finalized"] <= block.slot,
            "data": {
                "root": block.root.hex(),
                "canonical": True,
                "header": {
                    "message": {
                        "slot": block.slot,
                        "proposer_index": -1,
                        "parent_root": block.parent_root.hex(),
                        "state_root": block.state.hash_tree_root.hex(),
                        "body_root": "Unsupported"
                    },
                    "signature": "fake signature"
                },
            }
        }
        return jsonify(response)

    def get_beacon_state(self, state_id):
        block = self._find_block_for_state(state_id)

        accept_header = request.headers.get('Accept')
        beacon_state = block.state

        if accept_header == 'application/octet-stream':
            return send_file(
                io.BytesIO(ssz.encode(beacon_state, BeaconState)),
                mimetype=accept_header,
                as_attachment=True,
                download_name=f"beacon_state_{block.slot}.ssz"
            )
        elif accept_header == 'application/json':
            json_data = json.dumps(beacon_state, cls=JsonEncoder)
            return jsonify(json_data)
        else:
            return 'Unsupported Media Type', 415

    def get_beacon_root(self, state_id):
        block = self._find_block_for_state(state_id)

        return jsonify({"data": {"root": block.root.hex()}})

    def get_beacon_block(self, state_id):
        block = self._find_block_for_state(state_id)

        data = {
            "slot": block.slot,
            "proposer_index": -1,
            "parent_root": block.parent_root.hex(),
            "state_root": block.state.hash_tree_root.hex(),
            "body": {
                "execution_payload": {
                    'block_number': block.slot,
                    'block_hash': block.root.hex(),
                    'timestamp': 1234567890,
                }
            }
        }
        return jsonify({"message": data, "signature": "fake signature"})

    def set_chain_pointers(self, head: Optional[int] = None, finalized: Optional[int] = None, justified: Optional[int] = None):
        self.states['head'] = int(head) if head is not None else self.states['head']
        self.states['finalized'] = int(finalized) if finalized is not None else self.states['finalized']
        self.states['justified'] = int(justified) if justified is not None else self.states['justified']

    def add_state(self, slot: int, beacon_block_root: HexBytes, parent_root: HexBytes, beacon_state: BeaconState):
        assert slot not in self._beacon_blocks
        block = BeaconBlock(slot, root=beacon_block_root, parent_root=parent_root, state=beacon_state)
        self._beacon_blocks[slot] = block

    def start_server(self):
        self.app.run()

    def start_nonblocking(self, host = "localhost", port = 5000):
        self._server_thread = ServerThread(self.app, host, port)
        self._server_thread.start()

    def terminate(self):
        self._server_thread.shutdown()
        self._server_thread.join(5)