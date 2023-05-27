import start_utils

start_utils.init_paths()
start_utils.change_working_dir(start_utils.Submodules.LIDO_ORACLE)

from scripts.gen_report import main, ArgumentParser
from scripts.utils import Chain

parser = ArgumentParser(
    module = "accounting_min",
    slot = None,
    chain = Chain.MAINNET
)

main(parser)
