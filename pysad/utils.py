#!/usr/bin/env python3

from __future__ import annotations
from collections.abc import Iterable
from copy import deepcopy
from functools import wraps
from typing import Any, cast
from models import ABITypes
from pysad.errors import BinaryDataError, MismatchedABI
from pysad.models import DecodedABI

from eth_abi.grammar import parse, ABIType, TupleType
from eth_utils.abi import (
    event_abi_to_log_topic,
    function_abi_to_4byte_selector,
    collapse_if_tuple,
)

from pyevmasm import Instruction, disassemble_all
from itertools import starmap


def hex_to_bytes(input: str | bytes) -> bytes:
    if isinstance(input, (bytes, bytearray, memoryview)):
        return bytes(input)
    elif isinstance(input, str):
        return bytes.fromhex(input.removeprefix("0x"))
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


def fix_log_types(types: list[str], rtypes: list[bool]) -> list[str]:
    # reference structures are stored in log topics as the sha3 hash of the structure
    return ["bytes32" if b else t for (t, b) in zip(types, rtypes)]


def get_log_inputs(inputs: list[dict]) -> tuple[list[bool], list[bool]]:
    reference = [is_reference_type(t) for t in inputs]
    indexed = [t["indexed"] for t in inputs]
    return reference, indexed


def fix_reference_log_inputs(inputs: list[dict]) -> list[dict]:
    _inputs = deepcopy(inputs)
    for i in _inputs:
        if is_reference_type(i):
            i["type"] = "bytes32"
            del i["inputs"]
    return _inputs


def is_equivalent_runtime_opcode(op1: Instruction, op2: Instruction):
    # Handle the case of immutable value substitution
    if op2.name.startswith("PUSH"):
        return op1.name == op2.name and (op1.operand == op2.operand or op1.operand == 0)
    return op1.name == op2.name


def extract_constructor_args(input: bytes, bytecode: bytes) -> bytes | None:

    init_bytecode = list(disassemble_all(input))
    runtime_bytecode = list(disassemble_all(bytecode))

    for i in range(0, len(input) - len(bytecode)):
        if all(
            starmap(is_equivalent_runtime_opcode, zip(init_bytecode, runtime_bytecode))
        ):
            # constructor_code = input[:i]
            # runtime_bytecode = input[i : len(bytecode)]
            constructor_args = input[i + len(bytecode) :]
            return constructor_args


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
