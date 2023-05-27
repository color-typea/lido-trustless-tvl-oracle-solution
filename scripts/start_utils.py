from dataclasses import dataclass
import os.path
import sys
from typing import List

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
MODULES = os.path.join(PROJECT_ROOT, "modules")

@dataclass
class Submodule:
    name: str
    relative_path: str
    sources: List[str]

    @property
    def abspath(self):
        return os.path.join(MODULES, self.relative_path)


class Submodules:
    LIDO_ORACLE = Submodule("lido-oracle", "lido-oracle", ["src", "scripts"])

    ALL = [LIDO_ORACLE]


def init_paths():
    for submodule in Submodules.ALL:
        for path in submodule.sources:
            include_path = os.path.join(submodule.abspath, path)

            _append_to_path(include_path)


def change_working_dir(submodule: Submodule):
    os.chdir(submodule.abspath)

def _append_to_path(folder):
    sys.path.append(folder)