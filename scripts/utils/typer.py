#!/usr/bin/env python3

import asyncio
from functools import wraps
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Awaitable,
    Callable,
    Concatenate,
    Coroutine,
    Optional,
    ParamSpec,
    TypeVar,
)

from dotenv import load_dotenv
from merge_args import merge_args

import typer

P = ParamSpec("P")
R = TypeVar("R")


class AsyncTyper(typer.Typer):
    def async_command(self, *args, **kwargs):
        def decorator(
            async_func: Callable[P, Coroutine[Any, Any, R]]
        ) -> Callable[P, R]:
            @wraps(async_func)
            def sync_func(*args: P.args, **kwargs: P.kwargs) -> R:
                return asyncio.run(async_func(*args, **kwargs))

            return self.command(*args, **kwargs)(sync_func)

        return decorator


Q = ParamSpec("Q")
S = TypeVar("S")


def with_env(
    func: Callable[Q, Coroutine[Any, Any, S]]
) -> Callable[Concatenate[Optional[Path], Q], Coroutine[Any, Any, S]]:
    @merge_args(func)
    async def inner(
        env: Annotated[Optional[Path], typer.Option(help="Environment File")] = None,
        *args: Q.args,
        **kwargs: Q.kwargs,
    ) -> S:
        if env:
            load_dotenv(env)

        return await func(*args, **kwargs)

    return inner
