#!/bin/bash
SCRIPT_PATH=/home/john/Projects/crypto/zkllvm/lido-trustless-tvl-oracle-solution/utils
/home/john/.cache/pypoetry/virtualenvs/lido-trustless-tlv-solution-GpgdDnWG-py3.10/bin/python ${SCRIPT_PATH}/beacon_state_downloader.py -c goerli frame >>${SCRIPT_PATH}/exec.log 2>&1