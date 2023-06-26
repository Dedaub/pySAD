""""
Precompiled functions exist on-chain to reduce gas cost for commonly used functions.
This file creates special cases for decoding these contracts.

On the main chain, these exist ot addresses 0x000...01 to 0x000...09.
A list of these functions is available here: https://www.evm.codes/precompiled
"""


from typing import Any

from eth_abi.abi import decode

from pysad.errors import DecodingError, UnknownPrecompile
from pysad.utils import get_input_info, hex_to_bytes, named_tree


def get_precompiled_abi(address: bytes | str) -> dict | None:
    return PRECOMPILED_MAP.get(hex_to_bytes(address))


def decode_precompiled(address: bytes | str, input: bytes | str) -> dict[str, Any]:
    """
    Decode calldata for precompiled functions.
    Returns a dict mapping the function's parameters to their values.
    """

    # Precompiled functions do not have a selector, so the entire input is calldata
    calldata = hex_to_bytes(input)

    # Check if this is actually a precompiled function
    if (abi := get_precompiled_abi(address)) is None:
        raise UnknownPrecompile(address)

    # Check if a special case is needed to handle this function
    if case_handler := SPECIAL_CASES.get(abi["name"]):
        return case_handler(abi, calldata)

    # Decode the function normally
    types, _ = get_input_info(abi["inputs"])
    try:
        args = decode(types, calldata)
    except Exception as e:
        raise DecodingError from e

    return named_tree(abi["inputs"], args)


def decode_single_input(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode functions with a single argument.
    eg. sha256, ripemd160, identity

    Since there is only one argument, all calldata corresponds to this value.
    """

    return named_tree(abi["inputs"], [calldata])


def decode_modexp(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode modexp function input.
    function modexp(Bsize, Esize, Msize, B, E, M)
    where Bsize, Esize and Msize and the size in bytes of B, E, M respectively
    """

    # Read the byte size of argument. Each size is given as an uint32
    if len(calldata) < 96:
        raise DecodingError

    Bsize = int.from_bytes(calldata[0:32], "big")
    Esize = int.from_bytes(calldata[32:64], "big")
    Msize = int.from_bytes(calldata[64:96], "big")

    if len(calldata[96:]) < Bsize + Esize + Msize:
        raise DecodingError

    return named_tree(
        abi["inputs"],
        [
            Bsize,  # Bsize
            Esize,  # Esize
            Msize,  # Msize
            calldata[96 : (96 + Bsize)],  # B
            calldata[(96 + Bsize) : (96 + Bsize + Esize)],  # E
            calldata[(96 + Bsize + Esize) : (96 + Bsize + Esize + Msize)],  # M
        ],
    )


def decode_blake2f(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode blake2f function input.
    function blake2f(rounds: bytes4, h: bytes64, m: bytes128, t: bytes16, f: bytes1)
    """

    if len(calldata) != 213:
        raise DecodingError

    return named_tree(
        abi["inputs"],
        [
            calldata[0:4],
            calldata[4:68],
            calldata[68:196],
            calldata[196:212],
            calldata[212:213],
        ],
    )


# Map each precompiled function to its required decoder function
SPECIAL_CASES = {
    "sha256": decode_single_input,
    "ripemd160": decode_single_input,
    "identity": decode_single_input,
    "modexp": decode_modexp,
    "blake2f": decode_blake2f,
}


# Define precompiled function abis
PRECOMPILES = [
    # ecrecover
    {
        "selector": "0x6e150a4d",
        "signature": "ecrecover(bytes32,bytes32,bytes32,bytes32)",
        "name": "ecrecover",
        "inputs": [
            {"name": "hash", "type": "bytes32", "internalType": "bytes32"},
            {"name": "v", "type": "bytes32", "internalType": "bytes32"},
            {"name": "r", "type": "bytes32", "internalType": "bytes32"},
            {"name": "s", "type": "bytes32", "internalType": "bytes32"},
        ],
        "address": "0x0000000000000000000000000000000000000001",
        "outputs": [
            {"name": "publicAddress", "type": "address", "interalType": "address"},
        ],
        "stateMutability": "pure",
    },
    # sha256
    {
        "selector": "0xbebc76dd",
        "signature": "sha256(bytes)",
        "name": "sha256",
        "inputs": [
            {"name": "data", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000002",
        "outputs": [
            {"name": "hash", "type": "bytes32", "interalType": "bytes32"},
        ],
        "stateMutability": "pure",
    },
    # ripemd160
    {
        "selector": "0x9e641bf8",
        "signature": "ripemd160(bytes)",
        "name": "ripemd160",
        "inputs": [
            {"name": "data", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000003",
        "outputs": [
            {"name": "hash", "type": "bytes32", "interalType": "bytes32"},
        ],
        "stateMutability": "pure",
    },
    # identity
    {
        "selector": "0x840f6120",
        "signature": "identity(bytes)",
        "name": "identity",
        "inputs": [
            {"name": "data", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000004",
        "outputs": [
            {"name": "data", "type": "bytes", "interalType": "bytes"},
        ],
        "stateMutability": "pure",
    },
    # modexp
    {
        "selector": "0x99d63977",
        "signature": "modexp(uint32,uint32,uint32,bytes,bytes,bytes)",
        "name": "modexp",
        "inputs": [
            {"name": "Bsize", "type": "uint32", "internalType": "uint32"},
            {"name": "Esize", "type": "uint32", "internalType": "uint32"},
            {"name": "Msize", "type": "uint32", "internalType": "uint32"},
            {"name": "B", "type": "bytes", "internalType": "bytes"},
            {"name": "E", "type": "bytes", "internalType": "bytes"},
            {"name": "M", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000005",
        "outputs": [
            {"name": "value", "type": "bytes", "interalType": "bytes"},
        ],
        "stateMutability": "pure",
    },
    # ecadd
    {
        "selector": "0x3e69f620",
        "signature": "ecadd(bytes32,bytes32,bytes32,bytes32)",
        "name": "ecadd",
        "inputs": [
            {"name": "x1", "type": "bytes32", "internalType": "bytes32"},
            {"name": "y1", "type": "bytes32", "internalType": "bytes32"},
            {"name": "x2", "type": "bytes32", "internalType": "bytes32"},
            {"name": "y2", "type": "bytes32", "internalType": "bytes32"},
        ],
        "address": "0x0000000000000000000000000000000000000006",
        "outputs": [
            {"name": "x", "type": "bytes32", "interalType": "bytes32"},
            {"name": "y", "type": "bytes32", "interalType": "bytes32"},
        ],
        "stateMutability": "pure",
    },
    # ecmul
    {
        "selector": "0x6596c926",
        "signature": "ecmul(bytes32,bytes32,bytes32)",
        "name": "ecmul",
        "inputs": [
            {"name": "x1", "type": "bytes32", "internalType": "bytes32"},
            {"name": "y1", "type": "bytes32", "internalType": "bytes32"},
            {"name": "s", "type": "bytes32", "internalType": "bytes32"},
        ],
        "address": "0x0000000000000000000000000000000000000007",
        "outputs": [
            {"name": "x", "type": "bytes32", "interalType": "bytes32"},
            {"name": "y", "type": "bytes32", "interalType": "bytes32"},
        ],
        "stateMutability": "pure",
    },
    # ecpairing
    {
        "selector": "0xc9744441",
        "signature": "ecpairing(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)",
        "name": "ecpairing",
        "inputs": [
            {"name": "x1", "type": "bytes32", "internalType": "bytes32"},
            {"name": "y1", "type": "bytes32", "internalType": "bytes32"},
            {"name": "x2", "type": "bytes32", "internalType": "bytes32"},
            {"name": "y2", "type": "bytes32", "internalType": "bytes32"},
            {"name": "x3", "type": "bytes32", "internalType": "bytes32"},
            {"name": "y3", "type": "bytes32", "internalType": "bytes32"},
        ],
        "address": "0x0000000000000000000000000000000000000008",
        "outputs": [
            {"name": "success", "type": "bytes32", "interalType": "bytes32"},
        ],
        "stateMutability": "pure",
    },
    # blake2f
    # NOTE: These types are not technically correct, but precompiled functions do not actually have a proper abi
    {
        "selector": "0x5cd8a5b3",
        "signature": "blake2f(bytes4,bytes64,bytes128,bytes16,bytes1)",
        "name": "blake2f",
        "inputs": [
            {"name": "rounds", "type": "bytes4", "internalType": "bytes4"},
            {"name": "h", "type": "bytes64", "internalType": "bytes64"},
            {"name": "m", "type": "bytes128", "internalType": "bytes128"},
            {"name": "t", "type": "bytes16", "internalType": "bytes16"},
            {"name": "f", "type": "bytes1", "internalType": "bytes1"},
        ],
        "address": "0x0000000000000000000000000000000000000009",
        "outputs": [
            {"name": "h", "type": "bytes64", "internalType": "bytes64"},
        ],
        "stateMutability": "pure",
    },
]


# Map each address to its abi
PRECOMPILED_MAP = {hex_to_bytes(abi["address"]): abi for abi in PRECOMPILES}
