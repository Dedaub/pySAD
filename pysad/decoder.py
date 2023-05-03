#!/usr/bin/env python3

from collections import defaultdict
from itertools import starmap
from typing import Any

from eth_abi.abi import decode
from eth_utils.abi import (
    event_abi_to_log_topic,
    function_abi_to_4byte_selector,
    function_signature_to_4byte_selector,
)

from pysad.errors import DecodingError, UnknownABI
from pysad.signature import parse_signature
from pysad.types import ABITypes, SelectorABIMapping
from pysad.utils import (
    extract_constructor_args,
    fix_log_types,
    fix_reference_log_inputs,
    get_input_info,
    get_log_inputs,
    hex_to_bytes,
    named_tree,
)


class ABIDecoder:
    functions: SelectorABIMapping
    errors: SelectorABIMapping
    events: SelectorABIMapping
    constructor: dict | None

    def __init__(self, abi: list[dict]):
        self.functions = {}
        self.errors = {}
        self.events = {}
        self.constructor = None

        for entry in abi:
            type: ABITypes = entry["type"]

            if type == "constructor":
                self.constructor = entry
                continue

            if type == "function":
                selector = function_abi_to_4byte_selector(entry)
                self.functions[selector] = entry
            elif type == "error":
                selector = function_abi_to_4byte_selector(entry)
                self.errors[selector] = entry
            elif type == "event":
                selector = event_abi_to_log_topic(entry)
                self.events[selector] = entry

    def _decode_primitive(self, input: bytes | str, lookup: dict):
        input = hex_to_bytes(input)
        selector, calldata = input[:4], input[4:]
        func_abi = lookup[selector]
        if func_abi is None:
            raise UnknownABI()

        types, _ = get_input_info(func_abi["inputs"])
        try:
            args = decode(types, calldata)
        except Exception as e:
            raise DecodingError from e

        return named_tree(func_abi["inputs"], args)

    def decode_function(self, input: bytes | str):
        return self._decode_primitive(input, self.functions)

    def decode_error(self, input: bytes | str):
        return self._decode_primitive(input, self.errors)

    def decode_return(self, output: bytes | str, selector: str | bytes):
        output = hex_to_bytes(output)
        selector = hex_to_bytes(selector)
        func_abi = self.functions.get(selector)
        if func_abi is None:
            raise UnknownABI()
        return self._decode_primitive(
            (b"\x00" * 4) + output,
            defaultdict(
                lambda: {
                    "name": "return",
                    "inputs": func_abi["outputs"],  # type: ignore
                    "type": "function",
                }
            ),
        )

    def decode_event(self, topics: list[str] | list[bytes], memory: str | bytes):
        if len(topics) == 0:
            return {}

        topics = list(map(hex_to_bytes, topics))
        memory = hex_to_bytes(memory)

        selector = topics[0]
        topics = topics[1:]
        event_abi = self.events.get(selector)  # type: ignore
        if event_abi is None:
            raise UnknownABI

        types, _ = get_input_info(event_abi["inputs"])
        rtypes_bmap, index_bmap = get_log_inputs(event_abi["inputs"])
        types = fix_log_types(types, rtypes_bmap)

        topic_types = [[t] for (t, b) in zip(types, index_bmap) if b]
        memory_types = [t for (t, b) in zip(types, index_bmap) if not b]

        decoded_topics = list(
            # use lambda to extract tuple from decode
            map(lambda x: x[0], starmap(decode, zip(topic_types, topics)))
        )
        decoded_memory = list(decode(memory_types, memory))

        args = [
            decoded_topics.pop(0) if indexed else decoded_memory.pop(0)
            for indexed in index_bmap
        ]

        processed_abi = {k: v for k, v in event_abi.items() if k != "inputs"}
        processed_abi["inputs"] = fix_reference_log_inputs(event_abi["inputs"])

        return named_tree(processed_abi["inputs"], args)

    def decode_constructor(self, input: bytes | str, bytecode: bytes | str):

        if not self.constructor:
            raise UnknownABI()

        input = hex_to_bytes(input)
        bytecode = hex_to_bytes(bytecode)

        args = extract_constructor_args(input, bytecode)

        if args:
            return self._decode_primitive(
                (b"\x00" * 4) + args, defaultdict(lambda: self.constructor)
            )
        else:
            return None


class SignatureDecoder:
    selector: bytes
    name: str
    inputs: list[str]
    outputs: list[str]

    def __init__(self, signature: str):
        self.name, self.inputs, self.outputs = parse_signature(signature)
        self.selector = function_signature_to_4byte_selector(
            f'{self.name}({",".join(self.inputs)})'
        )

    def decode_input(self, input: str | bytes) -> tuple[Any, ...]:
        input = hex_to_bytes(input)
        if input.startswith(self.selector):
            input = input[4:]
        return decode(self.inputs, input)

    def decode_output(self, input: str | bytes) -> tuple[Any, ...]:
        input = hex_to_bytes(input)
        return decode(self.outputs, input)
