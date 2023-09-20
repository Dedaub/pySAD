#!/usr/bin/env python3

import argparse
import json
import os
import pprint as pp
import re
from typing import Literal

from eth_abi import encode
from eth_utils.abi import (
    _abi_to_signature,
    event_abi_to_log_topic,
    function_abi_to_4byte_selector,
)

parser = argparse.ArgumentParser(prog="Automate")


def main():
    parser.add_argument("solfiles")
    args = parser.parse_args()

    solfiles = args.solfiles.split(",")
    solinterfaces = [solfile.removesuffix(".sol") for solfile in solfiles]

    precompiles = {}

    for solfile, solinterface in zip(solfiles, solinterfaces):
        with open(solfile) as file:
            file_str = file.read()
            match = re.search("0x[0-9A-Fa-f]{40}", file_str)
            address = file_str[(start := match.start()) : start + 42]

        os.system(f"solc --abi --overwrite {solfile} -o {solinterface} > /dev/null")

        with open(f"{solinterface}/{solinterface}.abi") as abi:
            interface_abis = json.load(abi)

            abi_list = [
                abi
                | {
                    "selector": "0x"
                    + (
                        event_abi_to_log_topic(abi)
                        if abi["type"] == "event"
                        else function_abi_to_4byte_selector(abi)
                    ).hex(),
                    "signature": _abi_to_signature(abi),
                }
                for abi in interface_abis
            ]

            precompiles[address] = abi_list[0] if len(abi_list) == 1 else abi_list

    print(f"ARB_PRECOMPILES = {pp.pformat(precompiles)}")


if __name__ == "__main__":
    main()
