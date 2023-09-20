#!/usr/bin/env python3

import asyncio
from itertools import chain
from pprint import pformat, pprint
from typing import Any, cast

from fasteth.models import Log, LogsFilter
from fasteth.rpc import AsyncEthereumJSONRPC
from fasteth.types import ETHAddress, ETHBlockIdentifier
from psycopg import AsyncConnection, AsyncCursor
from pysad.arb_precompiles import ARB_PRECOMPILES
from pysad.decoder import ABIDecoder

from scripts.utils.common import Address
from scripts.utils.db import get_connstr
from scripts.utils.node import Network, get_node_url
from scripts.utils.typer import AsyncTyper, with_env

app = AsyncTyper()


async def get_address_transactions(
    cursor: AsyncCursor, to_address: Address, limit: int = 5
) -> list[tuple]:
    await cursor.execute(
        "select calldata from transaction_detail where to_a = %s limit %s",
        (bytes.fromhex(to_address.removeprefix("0x")), limit),
    )

    return await cursor.fetchall()


relevant_blocks = [46683330, 132861598, 132410410]


async def get_address_events(
    rpc: AsyncEthereumJSONRPC, cursor: AsyncCursor, address: Address, limit: int = 5
) -> list[tuple]:
    requests = [
        rpc.get_logs(
            LogsFilter(
                fromBlock=cast(ETHBlockIdentifier, block),
                toBlock=cast(ETHBlockIdentifier, block),
                address=ETHAddress.validate(address),
            )
        )
        for block in relevant_blocks
    ]

    responses: chain[Log] = chain.from_iterable(await asyncio.gather(*requests))

    return [(log.topics, log.data) for log in responses]


def decode_sample(
    decoder: ABIDecoder, abi: list[dict], sample: bytes
) -> dict[str, Any]:
    selector = f"0x{sample[:4].hex()}"

    specific_abi = {}

    for single_abi in abi:
        if single_abi["selector"] == selector:
            specific_abi = single_abi

    if specific_abi["type"] == "function":
        return decoder.decode_function(sample)

    if specific_abi["type"] == "error":
        return decoder.decode_error(sample)

    return {}


@app.async_command(help="Generate tests for Aribitrum precompiles")
@with_env
async def gen_arb_tests():
    all_others = []
    all_events = []

    async with AsyncEthereumJSONRPC(get_node_url(Network.ARBITRUM)) as rpc:
        async with await AsyncConnection.connect(get_connstr()) as conn:
            async with conn.cursor() as cursor:
                await cursor.execute("set search_path = arbitrum,common")

                for address, abi in ARB_PRECOMPILES.items():
                    abi = abi if isinstance(abi, list) else [abi]

                    decoder = ABIDecoder(abi)

                    transaction_samples = await get_address_transactions(
                        cursor, cast(Address, address)
                    )

                    if transaction_samples:
                        transaction_samples = [
                            (address, sample, decode_sample(decoder, abi, sample))
                            for (sample,) in transaction_samples
                        ]

                        all_others = all_others + transaction_samples

                    event_samples = await get_address_events(
                        rpc, cursor, cast(Address, address)
                    )

                    if event_samples:
                        event_samples = [
                            (
                                address,
                                topics,
                                data,
                                decoder.decode_event(topics, data),
                            )
                            for topics, data in event_samples
                        ]

                        all_events = all_events + event_samples

    print(f"TRANSACTION:\n{pformat(all_others)}\nEVENTS:\n{pformat(all_events)}")


if __name__ == "__main__":
    app()
