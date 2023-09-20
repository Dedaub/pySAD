#!/usr/bin/env python3

import os

from psycopg import AsyncCursor


def get_connstr() -> str:
    return f"""
        host={os.environ['PROD_DB_HOST']}
        dbname={os.environ['PROD_DB_NAME']}
        user={os.environ['PROD_DB_USER']}
        password={os.environ['PROD_DB_PASSWORD']}
        port={os.environ['PROD_DB_PORT']}
        """


async def get_arbitrum_head(cursor: AsyncCursor) -> int:
    await cursor.execute("select max(block_number) as head from logs")

    (head,) = await cursor.fetchone()

    return head
