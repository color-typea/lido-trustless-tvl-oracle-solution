import start_utils

start_utils.init_paths()
start_utils.change_working_dir(start_utils.Submodules.LIDO_ORACLE)

from scripts.beacon_state_report import main, ArgumentParser
from scripts.utils import Chain

parser = ArgumentParser(
    slot = None,
    chain = Chain.MAINNET,
    input_file = None,
    save_beacon_state = True,
    output_file = None
)

main(parser)
