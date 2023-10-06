#!/usr/bin/env python3

import os
from enum import Enum


class Network(Enum):
    ETHEREUM = "ethereum"
    FANTOM = "fantom"
    ARBITRUM = "arbitrum"
    BASE = "base"
    # BINANCE = "binance"
    # GNOSIS = "gnosis"


def get_node_url(network: Network) -> str:
    return (
        "http://"
        + os.environ.get("NODE_PORTAL_HOST", "localhost:8090")
        + f"/{network.value.lower()}"
    )
