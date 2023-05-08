#!/usr/bin/env python3


from typing import cast

from eth_abi.grammar import TupleType, parse

from pysad.errors import InvalidSignature


def parse_signature(signature: str) -> tuple[str, list[str], list[str]]:
    name, inputs, outputs = split_signature(signature)
    try:
        input_types = extract_types(inputs)
    except Exception as e:
        raise InvalidSignature("Unable to parse input types") from e

    if outputs == "":
        output_types = []
    else:
        try:
            output_types = extract_types(outputs)
        except Exception as e:
            raise InvalidSignature("Unable to parse output types") from e

    return name, input_types, output_types


def split_signature(signature: str) -> tuple[str, str, str]:
    # assumes a well formed signature
    func_name, io = (
        signature[: signature.find("(")],
        signature[signature.find("(") :],
    )
    inputs: str | None = None
    outputs: str | None = None

    depth = 0
    for i, c in enumerate(io, 1):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1

        if depth == 0:
            inputs = io[:i]
            outputs = io[i:]
            break
    else:
        raise InvalidSignature("Invalid ABI Signature")

    return func_name, inputs, outputs  # type: ignore


def extract_types(params: str) -> list[str]:
    return [c.to_type_str() for c in cast(TupleType, parse(params)).components]
