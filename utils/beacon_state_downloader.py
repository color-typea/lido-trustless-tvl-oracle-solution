import enum

import argparse

import logging

import math
import os.path
from http import HTTPStatus

import requests
from abc import abstractmethod, ABC

import time

import dataclasses
import validators
from requests import RequestException
from dotenv import load_dotenv

load_dotenv()

CURDIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.dirname(CURDIR)
BEACON_STATE_CACHE = os.path.join(PROJECT_DIR, "beacon_state_cache")

LOADER_URL = os.getenv('CONSENSUS_CLIENT_URI')
assert validators.url(LOADER_URL), f"LOADER_URL should be a valid url, {LOADER_URL} given"

MINUTES_WHILE_EPOCH_IS_DOWNLOADABLE = 60


@dataclasses.dataclass
class EpochConfig:
    seconds_per_slot: int
    slots_per_epoch: int
    genesis_timestamp: int

    @property
    def duration_seconds(self):
        return self.seconds_per_slot * self.slots_per_epoch

    def epoch_at(self, timestamp: int) -> 'Epoch':
        time_since_genesis = timestamp - self.genesis_timestamp
        return Epoch((time_since_genesis // self.duration_seconds) + 1, self)


@dataclasses.dataclass
class FrameConfig:
    initial_epoch: int
    epochs_per_frame: int


@dataclasses.dataclass
class Epoch:
    number: int
    config: EpochConfig

    EPPCHS_TO_SAFE = 1
    EPOCHS_TO_FINALITY = 2

    def shift(self, epochs: int):
        return Epoch(self.number + epochs, self.config)

    def next(self):
        return self.shift(1)

    def previous(self):
        return self.shift(-1)

    @property
    def first_slot(self):
        return self.config.slots_per_epoch * self.number

    @property
    def last_slot(self):
        return self.first_slot + self.config.slots_per_epoch - 1

    @property
    def duration_seconds(self):
        return self.config.slots_per_epoch * self.config.seconds_per_slot

    @property
    def start_time(self):
        return self.first_slot * self.config.seconds_per_slot + self.config.genesis_timestamp

    @property
    def end_time(self):
        return self.start_time + self.duration_seconds

    @property
    def estimated_finality_time(self):
        should_be_finalized_at_epoch = self.shift(self.EPOCHS_TO_FINALITY)
        return should_be_finalized_at_epoch.start_time

    @property
    def estimated_safe_time(self):
        should_be_finalized_at_epoch = self.shift(self.EPPCHS_TO_SAFE)
        return should_be_finalized_at_epoch.start_time


@dataclasses.dataclass
class LidoFrame:
    epoch: Epoch

    EPOCHS_PER_FRAME = 225

    def next(self):
        return LidoFrame(self.epoch.shift(self.EPOCHS_PER_FRAME))

    @property
    def ref_slot(self):
        return self.epoch.first_slot - 1


class ChainConfig(ABC):
    SECONDS_PER_DAY = 86400  # except leap seconds... but it'll take long to accumulate to affect anything

    @abstractmethod
    def epoch_config(self) -> EpochConfig:
        pass

    @abstractmethod
    def frame_config(self) -> FrameConfig:
        pass

    @property
    def now(self):
        return int(time.time())

    def create_epoch(self, epoch_number: int):
        return Epoch(epoch_number, self.epoch_config())

    def get_slot_at_timestamp(self, timestamp: int) -> int:
        return (timestamp - self.epoch_config().genesis_timestamp) // self.epoch_config().seconds_per_slot

    def get_epoch_at_timestamp(self, timestamp: int) -> Epoch:
        epoch_num = self.get_slot_at_timestamp(timestamp) // self.epoch_config().slots_per_epoch
        return Epoch(epoch_num, self.epoch_config())

    def current_slot(self):
        return self.get_slot_at_timestamp(self.now)

    def current_epoch(self) -> Epoch:
        return self.get_epoch_at_timestamp(self.now)

    def should_be_final(self, epoch: Epoch):
        current_epoch = self.current_epoch()
        return epoch.number + Epoch.EPOCHS_TO_FINALITY < current_epoch.number

    def time_to_start(self, epoch: Epoch):
        return max(epoch.start_time - self.now, 0)

    def time_to_finality(self, epoch: Epoch):
        return max(epoch.estimated_finality_time - self.now, 0)

    def time_to_safe(self, epoch: Epoch):
        return max(epoch.estimated_safe_time - self.now, 0)

    def get_current_frame(self) -> LidoFrame:
        return self.get_frame_at_timestamp(self.now)

    def get_frame_at_timestamp(self, timestamp: int) -> LidoFrame:
        return self._get_frame_at_index(self._compute_frame_index(timestamp))

    def _compute_frame_index(self, timestamp: int) -> int:
        epoch = self.get_epoch_at_timestamp(timestamp)
        frame_config = self.frame_config()
        assert epoch.number > frame_config.initial_epoch
        return (epoch.number - frame_config.initial_epoch) // frame_config.epochs_per_frame

    def _get_frame_start_epoch(self, frame_index) -> Epoch:
        """
        _get_frame_start_epoch(_compute_frame_index(tmiestamp)) != get_epoch_at_timestamp(timestamp)
        This is due to integer division - (a // b) * b = a - (a mod b).
        In this particular case it is also shifted by epochs_per_frame.

        P.S. There should be a way to simplify this math, but it's nt worth the trouble and potential
        bugs, at least at this time
        """
        frame_config = self.frame_config()
        epoch_number = frame_config.initial_epoch + frame_index * frame_config.epochs_per_frame
        return Epoch(epoch_number, self.epoch_config())

    def _get_frame_at_index(self, index) -> LidoFrame:
        return LidoFrame(self._get_frame_start_epoch(index))


class Mainnet(ChainConfig):
    def epoch_config(self) -> EpochConfig:
        return EpochConfig(12, 32, 1606824023)

    def frame_config(self) -> FrameConfig:
        return FrameConfig(201600, 225)


class Goerli(ChainConfig):
    def epoch_config(self) -> EpochConfig:
        return EpochConfig(12, 32, 1616508000)

    def frame_config(self) -> FrameConfig:
        return FrameConfig(174520, 225)


class BeaconStateLoader:
    BEACON_STATE_ENPOINT = '/eth/v2/debug/beacon/states/{}'

    def __init__(self, base_url):
        self.base_url = base_url

    def load(self, state_id, retries: int = 3, wait: int = 120):
        attempts = 0
        while True:
            try:
                self._load(state_id)
                return
            except RequestException as e:
                attempts = attempts + 1
                if attempts >= retries:
                    logging.exception("Reached maximum number of attempts")
                    raise e
                else:
                    logging.warning(f"Attempt {attempts}: Failed to load {state_id}")
                    time.sleep(wait)

    def _load(self, state_id):
        destination_file_name = os.path.join(BEACON_STATE_CACHE, f"bs_{state_id}.ssz")

        url = self.base_url + self.BEACON_STATE_ENPOINT.format(state_id)
        with requests.get(url, headers={"Accept": "application/octet-stream"}) as response:
            if response.status_code != HTTPStatus.OK:
                response.raise_for_status()

            with open(destination_file_name, 'wb') as destination:
                for chunk in response.iter_content(chunk_size=8192):
                    destination.write(chunk)


def get_config(chain):
    if chain == 'goerli':
        return Goerli()
    else:
        return Mainnet()


def load_most_recent_frame(args):
    logging.info("Loading most recent frame")
    chain = get_config(args.chain)
    loader = BeaconStateLoader(LOADER_URL)

    frame = chain.get_current_frame()

    if chain.time_to_safe(frame.next().epoch) < 60 * 60: # 1 h
        frame = LidoFrame(frame.epoch.next())

    if frame.epoch.start_time > chain.now or frame.epoch.estimated_safe_time > chain.now:
        wait = chain.time_to_safe(frame.epoch)
        logging.info(f"We're early - waiting {wait}s for epoch to become safe")
        time.sleep(wait)
    elif (chain.now - frame.epoch.start_time) // 60 > MINUTES_WHILE_EPOCH_IS_DOWNLOADABLE:
        minutes_since_start = (chain.now - frame.epoch.start_time) / 60
        logging.warning(
            f"We're late, {minutes_since_start:.2f}min since epoch start (vs. {MINUTES_WHILE_EPOCH_IS_DOWNLOADABLE})"
            f"  - trying to download the epoch {frame.epoch} will likely fail"
        )

    logging.info(f"Loading state for current frame: epoch {frame.epoch.number}, slot {frame.ref_slot}")
    loader.load(frame.ref_slot)
    if args.sleep:
        put_to_sleep()


def load_continuous(args):
    logging.info(f"Continuous loading with {args.interval} interval and {args.limit} limit")
    chain = get_config(args.chain)
    loader = BeaconStateLoader(LOADER_URL)

    current_epoch = chain.current_epoch()
    start_loading_from = math.ceil(current_epoch.number / args.interval) * args.interval
    first_target_epoch = chain.create_epoch(start_loading_from)

    iterations = 0
    current_epoch = first_target_epoch
    while args.limit is None or iterations < args.limit:
        wait = chain.time_to_safe(current_epoch)
        logging.info(
            f"Iteration {iterations} start, waiting {wait}s for epoch {current_epoch.number} to reach safe state"
        )
        time.sleep(wait)
        loader.load(current_epoch.last_slot, retries=3, wait=120)
        iterations += 1
        current_epoch = current_epoch.shift(args.interval)

    logging.info(f"Finished loading")
    if args.sleep:
        put_to_sleep()


def load_single(args):
    logging.info(f"Loading single slot {args.slot}")
    loader = BeaconStateLoader(LOADER_URL)
    loader.load(args.slot)

    if args.sleep:
        put_to_sleep()


def put_to_sleep():
    import psutil
    if psutil.OSX:
        os.system("pmset sleepnow")
    elif psutil.LINUX:
        os.system("systemctl suspend")
    elif psutil.WINDOWS:
        raise ValueError("computer_sleep Not Implemented for WINDOWS")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument( "-c", "--chain", default="goerli")
    parser.add_argument("--sleep", default=False, action="store_true", help="Sleep after completing")
    subparsers = parser.add_subparsers(required=True)

    frame = subparsers.add_parser("frame")
    frame.set_defaults(func=load_most_recent_frame)

    single = subparsers.add_parser("single")
    single.add_argument("--slot", type=int, required=True)
    single.set_defaults(func=load_single)

    continuous = subparsers.add_parser("continuous")
    continuous.add_argument("--interval", "-i", type=int, required=True)
    continuous.add_argument("--limit", "-l", type=int, required=False, default=None)
    continuous.set_defaults(func=load_continuous)

    args = parser.parse_args()
    args.func(args)
