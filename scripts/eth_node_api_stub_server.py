import logging

import ssz
from ssz.hashable_list import HashableList
from ssz.hashable_vector import HashableVector
from typing import Optional

import json

import threading
from flask import Flask, jsonify, send_file, request

from scripts.eth_consensus_layer_ssz import BeaconState, EnhancedHashableContainer

LOGGER = logging.getLogger(__name__)

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, EnhancedHashableContainer):
            return obj.as_dict()
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, (HashableVector, HashableList)):
            return obj.elements.tolist()
        return super().default(obj)


class ServerThread(threading.Thread):
    def __init__(self, app, host, port):
        from werkzeug.serving import make_server
        super().__init__()
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        LOGGER.info('starting server')
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

class StubEthApiServer:
    def __init__(self):
        self.app = Flask(__name__)

        self.states = {
            'head': 0,
            'finalized': 0,
            'justified': 0
        }
        self.beacon_block_roots = dict()
        self.beacon_states = dict()

        self._init_routes()

    def _init_routes(self):
        self.app.route('/eth/v1/beacon/headers', methods=['GET'])(self.get_header)
        self.app.route('/eth/v2/debug/beacon/states/<state_id>', methods=['GET'])(self.get_beacon_state)

    def _replace_state_literal(self, state_literal) -> int:
        if state_literal in self.states:
            return self.states[state_literal]
        else:
            return int(state_literal)

    def get_header(self):
        slot = request.args.get('slot')
        state_id = self._replace_state_literal(slot)
        beacon_block_root = self.beacon_block_roots[state_id]
        data = {
            "root": beacon_block_root.hex(),
            "header": {
                "message": {
                    "slot": state_id,
                    # "proposer_index": -1,
                    # "parent_root": "Unsupported",
                    # "state_root": "Unsupported",
                    # "body_root": "Unsupported",
                }
            },
            # "signature": "Unsupported"
        }
        return jsonify({"data": [data]})

    def get_beacon_state(self, state_id):
        state_id = self._replace_state_literal(state_id)

        accept_header = request.headers.get('Accept')
        beacon_state = self.beacon_states[state_id]

        if accept_header == 'application/octet-stream':
            return send_file(
                ssz.encode(beacon_state, BeaconState),
                mimetype='application/octet-stream',
                as_attachment=True,
            )
        elif accept_header == 'application/json':
            json_data = json.dumps(beacon_state, cls=JsonEncoder)
            return jsonify(json_data)
        else:
            return 'Unsupported Media Type', 415

    def set_chain_pointers(self, head: Optional[int] = None, finalized: Optional[int] = None, justified: Optional[int] = None):
        self.states['head'] = int(head) if head is not None else self.states['head']
        self.states['finalized'] = int(finalized) if finalized is not None else self.states['finalized']
        self.states['justified'] = int(justified) if justified is not None else self.states['justified']

    def add_state(self, slot: int, beacon_block_root: bytes, beacon_state: BeaconState):
        assert slot not in self.beacon_block_roots
        assert slot not in self.beacon_states
        self.beacon_block_roots[slot] = beacon_block_root
        self.beacon_states[slot] = beacon_state

    def start_server(self):
        self.app.run()

    def start_nonblocking(self, host = "localhost", port = 5000):
        self._server_thread = ServerThread(self.app, host, port)
        self._server_thread.start()

    def terminate(self):
        self._server_thread.shutdown()
        self._server_thread.join(5)