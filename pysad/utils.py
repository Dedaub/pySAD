#!/usr/bin/env python3

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from itertools import starmap
from typing import Any, cast

from eth_abi.grammar import ABIType, TupleType, parse
from eth_utils.abi import collapse_if_tuple
from pyevmasm import Instruction, assemble_all, assemble_hex, disassemble_all

from pysad.errors import BinaryDataError, MismatchedABI


def hex_to_bytes(input: str | bytes) -> bytes:
    if isinstance(input, (bytes, bytearray, memoryview)):
        return bytes(input)
    elif isinstance(input, str):
        normalized_hex = input.removeprefix("0x")
        left_padding = "0" if len(normalized_hex) % 2 else ""

        return bytes.fromhex(f"{left_padding}{normalized_hex}")
    else:
        raise BinaryDataError("Unable to decode input")


# https://docs.soliditylang.org/en/latest/types.html#reference-types
# "Currently, reference types comprise structs, arrays and mappings."
def is_reference_type(arg: dict) -> bool:
    type = arg["type"]
    if type == "tuple" or type == "string" or type.endswith("]"):
        return True
    return False


def get_input_info(inputs: list[dict]) -> tuple[list[str], list[str]]:
    names = [i["name"] for i in inputs]
    types = [collapse_if_tuple(t) for t in inputs]
    return types, names


def fix_log_types(
    types: list[str], rtypes: list[bool], index_bmap: list[bool]
) -> list[str]:
    # reference structures are stored in log topics as the sha3 hash of the structure
    return ["bytes32" if b and i else t for (t, b, i) in zip(types, rtypes, index_bmap)]


def get_log_inputs(inputs: list[dict]) -> tuple[list[bool], list[bool]]:
    reference = [is_reference_type(t) for t in inputs]
    indexed = [t["indexed"] for t in inputs]
    return reference, indexed


def fix_reference_log_inputs(inputs: list[dict]) -> list[dict]:
    _inputs = deepcopy(inputs)
    for i in _inputs:
        if is_reference_type(i):
            i["type"] = "bytes32"
    return _inputs


def is_equivalent_runtime_opcode(runtime: Instruction, init: Instruction):
    # Handle the case of immutable value substitution
    if init.name.startswith("PUSH"):
        return runtime.name == init.name and (
            runtime.operand == init.operand or init.operand == 0
        )
    return runtime.name == init.name


def extract_constructor_args(input: bytes, bytecode: bytes) -> bytes | None:
    init_bytecode = list(disassemble_all(input))
    runtime_bytecode = list(disassemble_all(bytecode))

    for i in range(0, len(input) - len(bytecode)):
        if all(
            starmap(
                is_equivalent_runtime_opcode, zip(runtime_bytecode, init_bytecode[i:])
            )
        ):
            # need to convert things back to bytecode from
            # the instructions list since the indicies don't line up
            constructor_bytecode = init_bytecode[:i]
            constructor_length = len(hex_to_bytes(assemble_hex(constructor_bytecode)))
            return input[constructor_length + len(bytecode) :]

    return None


def named_tree(
    abi: Iterable[dict],
    data: Iterable[tuple],
) -> dict[str, Any]:
    """
    Convert function inputs/outputs or event data tuple to dict with names from ABI.
    """
    names = [item["name"] for item in abi]
    items = [_named_subtree(*item) for item in zip(abi, data)]
    return dict(zip(names, items))


SubTree = tuple | dict[str, Any] | list["SubTree"]


def _named_subtree(
    abi: dict,
    data: tuple,
) -> SubTree:
    abi_type = cast(ABIType, parse(collapse_if_tuple(dict(abi))))

    if abi_type.is_array:
        item_type = abi_type.item_type.to_type_str()
        item_abi = {**abi, "type": item_type, "name": ""}
        items = [_named_subtree(item_abi, item) for item in data]
        return items

    elif isinstance(abi_type, TupleType):
        names = [item["name"] for item in abi["components"]]
        items = [_named_subtree(*item) for item in zip(abi["components"], data)]

        if len(names) == len(data):
            return dict(zip(names, items))
        else:
            raise MismatchedABI(
                f"ABI fields {names} has length {len(names)} but received "
                f"data {data} with length {len(data)}"
            )

    return data
