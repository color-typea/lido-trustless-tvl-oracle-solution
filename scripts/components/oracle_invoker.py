import sys

import os

from typing import List, Optional

import subprocess

from dataclasses import dataclass

from eth_typing import HexStr
from pathlib import Path


@dataclass
class OracleInvokerEnv:
    execution_api_uri: str
    consensus_api_uri: str
    bs_api_uri: str
    locator_address: HexStr
    zktvk_contract_address: HexStr

    def to_env_dict(self) -> dict[str, str]:
        return {
            "BEACON_STATE_CLIENT_URI": self.bs_api_uri,
            "CONSENSUS_CLIENT_URI": self.consensus_api_uri,
            "EXECUTION_CLIENT_URI": self.execution_api_uri,
            "LIDO_LOCATOR_ADDRESS": self.locator_address,
            "ZKTVL_CONTRACT_ADDRESS": self.zktvk_contract_address,
        }


class OracleInvoker:
    def __init__(
            self, python, script, env: OracleInvokerEnv, account: Optional[HexStr] = None, cwd=None, pipe_output=False,
            args: List[str] = None, named_args: dict[str, str] = None
    ):
        self.python = python
        self.script = script
        self._cwd = cwd
        self.env = env
        self.pipe_output = pipe_output
        self.account = account
        self.positional_args = args if args else []
        self._named_args = named_args if named_args else dict()

    def _flatten_named_args(self, named_args: dict[str, str]) -> List[str]:
        return [
            item
            for key, value in named_args.items()
            for item in (key, value)
        ]

    @property
    def cwd(self) -> Path:
        value = self._cwd if self._cwd else "."
        return Path(value)

    @property
    def named_args(self):
        value = self._named_args
        if self.account is not None:
            value = value | {"-a": self.account}
        return value

    def _get_subprocess_args_kwargs(self, **kwargs):
        args = [self.python, "-m", self.script] + self.positional_args + self._flatten_named_args(
            self.named_args
        ) + self._flatten_named_args(kwargs)
        subprocess_kwargs = {
            "env": self.env.to_env_dict(),
            "check": True,
            "cwd": self.cwd,
        }
        if self.pipe_output:
            pipe_kwargs = {
                "stdout": sys.stdout,  # needed for the next line to be sensible
                "stderr": sys.stderr,
            }
            subprocess_kwargs = subprocess_kwargs | pipe_kwargs
        return args, subprocess_kwargs

    def run(self, **kwargs):
        args, subprocess_kwargs = self._get_subprocess_args_kwargs(**kwargs)
        process = subprocess.run(args, **subprocess_kwargs)
        if process.returncode != 0:
            raise Exception(f"Failed to run oracle - retcode {process.returncode}")

    def print_env_and_command(self):
        args, subprocess_kwargs = self._get_subprocess_args_kwargs()
        print(
            f"""
                    {args},
                    env={subprocess_kwargs['env']},
                    cwd={subprocess_kwargs['cwd']},
                    check=True, cwd={self.cwd},
                """
        )
