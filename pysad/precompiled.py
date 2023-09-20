""""
Precompiled functions exist on-chain to reduce gas cost for commonly used functions.
This file creates special cases for decoding these contracts.

On the main chain, these exist ot addresses 0x000...01 to 0x000...09.
A list of these functions is available here: https://www.evm.codes/precompiled
"""


from itertools import starmap
from pprint import pprint
from typing import Any

from eth_abi.abi import decode

from pysad.arb_precompiles import ARB_PRECOMPILES
from pysad.errors import DecodingError, UnknownPrecompile
from pysad.utils import (
    fix_log_types,
    fix_reference_log_inputs,
    get_input_info,
    get_log_inputs,
    hex_to_bytes,
    named_tree,
)


def get_precompiled_abi(
    address: bytes | str, selector: bytes | str
) -> tuple[bool, dict] | None:
    address_abi = PRECOMPILED_MAP.get(hex_to_bytes(address))

    if isinstance(address_abi, list):
        for method in address_abi:
            if method["selector"] == hex_to_bytes(selector):
                return True, method

    if isinstance(address_abi, dict):
        return False, address_abi

    return None


def decode_precompiled_event(
    address: bytes | str, topics: list[str] | list[bytes], memory: str | bytes
) -> dict[str, Any]:
    """
    Decode calldata for precompiled events.
    Returns a dict mapping the events's parameters to their values.
    """
    topics = list(map(hex_to_bytes, topics))
    memory = hex_to_bytes(memory)

    selector = topics[0]
    topics = topics[1:]

    # Check if this is actually a precompiled event
    if (use_abi := get_precompiled_abi(address, selector)) is None:
        raise UnknownPrecompile(address, selector)

    _, abi = use_abi

    types, _ = get_input_info(abi["inputs"])
    rtypes_bmap, index_bmap = get_log_inputs(abi["inputs"])
    types = fix_log_types(types, rtypes_bmap, index_bmap)

    topic_types = [[t] for (t, b) in zip(types, index_bmap) if b]
    memory_types = [t for (t, b) in zip(types, index_bmap) if not b]

    decoded_topics = map(lambda x: x[0], starmap(decode, zip(topic_types, topics)))
    decoded_memory = iter(decode(memory_types, memory))

    args = [
        next(decoded_topics) if indexed else next(decoded_memory)
        for indexed in index_bmap
    ]

    processed_abi = {k: v for k, v in abi.items() if k != "inputs"}
    processed_abi["inputs"] = fix_reference_log_inputs(abi["inputs"])

    return named_tree(processed_abi["inputs"], args)


def decode_precompiled(address: bytes | str, input_data: bytes | str) -> dict[str, Any]:
    """
    Decode calldata for precompiled functions and errors.
    Returns a dict mapping the function/error's parameters to their values.
    """

    # Precompiled functions do not have a selector, so the entire input is calldata
    calldata = hex_to_bytes(input_data)
    selector = calldata[:4]

    # Check if this is actually a precompiled function
    if (use_abi := get_precompiled_abi(address, selector)) is None:
        raise UnknownPrecompile(address, selector)

    has_selector, abi = use_abi

    # Check if a special case is needed to handle this function
    if case_handler := SPECIAL_CASES.get(abi["name"]):
        return case_handler(abi, calldata)

    # Decode the function normally
    types, _ = get_input_info(abi["inputs"])

    try:
        args = decode(types, calldata[4:] if has_selector else calldata)
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

    # Read the byte size of argument. Each size is given as a 32 byte uint (uint256)
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
            int.from_bytes(calldata[0:4], "big"),  # rounds
            calldata[4:68],  # h
            calldata[68:196],  # m
            calldata[196:212],  # t
            calldata[212:213],  # f
        ],
    )


def decode_validateTendermintHeader(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode validateTendermintHeader function input.
    validateTendermintHeader is a precompile on the BNB chain.
    function validateTendermintHeader(length: uint256, chainID: uint256, height: uint64, appHash: bytes32, curValidatorSetHash: bytes32, nextValidatorSet: bytes, header: bytes)
    """

    # Calldata Layout:
    # Value: | length   | chainID  | height  | appHash  | curValidatorSetHash | nextValidatorSet | header          |
    # Size:  | 32 bytes | 32 bytes | 8 bytes | 32 bytes | 32 bytes            | length bytes     | remaining bytes |

    length = int.from_bytes(calldata[0:32], "big")
    chainID = int.from_bytes(calldata[32:64], "big")
    height = int.from_bytes(calldata[64:72], "big")
    appHash = calldata[72:104]
    curValidatorSetHash = calldata[104:136]
    nextValidatorSet = calldata[136 : length + 32]
    header = calldata[length + 32 :]

    return named_tree(
        abi["inputs"],
        [
            length,
            chainID,
            height,
            appHash,
            curValidatorSetHash,
            nextValidatorSet,
            header,
        ],
    )


def decode_verifyMerkleProof(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode verifyMerkleProof function input.
    verifyMerkleProof is a precompile on the BNB chain.
    function verifyMerkleProof(storeName: string, keyLength: uint256, key: bytes, valueLength: uint256, value: bytes, appHash: uint256, proof: bytes)
    """

    # Calldata Layout:
    # Value: | storeName | keyLength | key             | valueLength | value           | appHash  | proof           |
    # Size:  | 32 bytes  | 32 bytes  | keyLength bytes | 32 bytes    | keyLength bytes | 32 bytes | remaining bytes |

    storeName = calldata[0:32].decode()
    keyLength = int.from_bytes(calldata[32:64], "big")
    key = calldata[64 : 64 + keyLength]
    valueLength = int.from_bytes(calldata[64 + keyLength : 96 + keyLength], "big")
    value = calldata[96 + keyLength : 96 + keyLength + valueLength]
    appHash = calldata[96 + keyLength + valueLength : 128 + keyLength + valueLength]
    proof = calldata[128 + keyLength + valueLength :]

    return named_tree(
        abi["inputs"],
        [
            storeName,
            keyLength,
            key,
            valueLength,
            value,
            appHash,
            proof,
        ],
    )


def decode_verifyBLSSignature(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode verifyBLSSignature function input.
    verifyBLSSignature is a precompile on the BNB chain.
    function verifyBLSSignature(vote: bytes32, voteSignature: bytes, voteAddress: bytes)
    """

    if len(calldata) != 176:
        raise DecodingError

    vote = calldata[0:32]
    voteSignature = calldata[32:128]
    voteAddress = calldata[128:176]

    return named_tree(
        abi["inputs"],
        [
            vote,
            voteSignature,
            voteAddress,
        ],
    )


def decode_BFTLightBlockValidate(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode BFTLightBlockValidate function input.
    BFTLightBlockValidate is a precompile on the BNB chain.
    function BFTLightBlockValidate(consensusStateLength: uint256, consensusState: bytes, lightBlock: bytes)
    """

    consensusStateLength = int.from_bytes(calldata[0:32], "big")
    consensusState = calldata[32 : 32 + consensusStateLength]
    lightBlock = calldata[32 + consensusStateLength :]

    return named_tree(
        abi["inputs"],
        [
            consensusStateLength,
            consensusState,
            lightBlock,
        ],
    )


# Map each precompiled function to its required decoder function
SPECIAL_CASES = {
    "sha256": decode_single_input,
    "ripemd160": decode_single_input,
    "identity": decode_single_input,
    "modexp": decode_modexp,
    "blake2f": decode_blake2f,
    "validateTendermintHeader": decode_validateTendermintHeader,
    "verifyMerkleProof": decode_verifyMerkleProof,
    "verifyBLSSignature": decode_verifyBLSSignature,
    "BFTLightBlockValidate": decode_BFTLightBlockValidate,
}


# Define precompiled function abis
# NOTE: The selectors included have been manually added for conformity. Precompiled functions do not actually have selectors.
PRECOMPILES = ARB_PRECOMPILES | {
    # ecrecover
    "0x0000000000000000000000000000000000000001": {
        "inputs": [
            {"internalType": "bytes32", "name": "hash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "v", "type": "bytes32"},
            {"internalType": "bytes32", "name": "r", "type": "bytes32"},
            {"internalType": "bytes32", "name": "s", "type": "bytes32"},
        ],
        "name": "ecrecover",
        "outputs": [
            {"interalType": "address", "name": "publicAddress", "type": "address"}
        ],
        "selector": "0x6e150a4d",
        "signature": "ecrecover(bytes32,bytes32,bytes32,bytes32)",
        "stateMutability": "pure",
    },
    # sha256
    "0x0000000000000000000000000000000000000002": {
        "inputs": [{"internalType": "bytes", "name": "data", "type": "bytes"}],
        "name": "sha256",
        "outputs": [{"interalType": "bytes32", "name": "hash", "type": "bytes32"}],
        "selector": "0xbebc76dd",
        "signature": "sha256(bytes)",
        "stateMutability": "pure",
    },
    # ripemd160
    "0x0000000000000000000000000000000000000003": {
        "inputs": [{"internalType": "bytes", "name": "data", "type": "bytes"}],
        "name": "ripemd160",
        "outputs": [{"interalType": "bytes32", "name": "hash", "type": "bytes32"}],
        "selector": "0x9e641bf8",
        "signature": "ripemd160(bytes)",
        "stateMutability": "pure",
    },
    # identity
    "0x0000000000000000000000000000000000000004": {
        "inputs": [{"internalType": "bytes", "name": "data", "type": "bytes"}],
        "name": "identity",
        "outputs": [{"interalType": "bytes", "name": "data", "type": "bytes"}],
        "selector": "0x840f6120",
        "signature": "identity(bytes)",
        "stateMutability": "pure",
    },
    # modexp
    "0x0000000000000000000000000000000000000005": {
        "inputs": [
            {"internalType": "uint256", "name": "Bsize", "type": "uint256"},
            {"internalType": "uint256", "name": "Esize", "type": "uint256"},
            {"internalType": "uint256", "name": "Msize", "type": "uint256"},
            {"internalType": "bytes", "name": "B", "type": "bytes"},
            {"internalType": "bytes", "name": "E", "type": "bytes"},
            {"internalType": "bytes", "name": "M", "type": "bytes"},
        ],
        "name": "modexp",
        "outputs": [{"interalType": "bytes", "name": "value", "type": "bytes"}],
        "selector": "0x99d63977",
        "signature": "modexp(uint256,uint256,uint256,bytes,bytes,bytes)",
        "stateMutability": "pure",
    },
    # ecadd
    "0x0000000000000000000000000000000000000006": {
        "inputs": [
            {"internalType": "bytes32", "name": "x1", "type": "bytes32"},
            {"internalType": "bytes32", "name": "y1", "type": "bytes32"},
            {"internalType": "bytes32", "name": "x2", "type": "bytes32"},
            {"internalType": "bytes32", "name": "y2", "type": "bytes32"},
        ],
        "name": "ecadd",
        "outputs": [
            {"interalType": "bytes32", "name": "x", "type": "bytes32"},
            {"interalType": "bytes32", "name": "y", "type": "bytes32"},
        ],
        "selector": "0x3e69f620",
        "signature": "ecadd(bytes32,bytes32,bytes32,bytes32)",
        "stateMutability": "pure",
    },
    # ecmul
    "0x0000000000000000000000000000000000000007": {
        "inputs": [
            {"internalType": "bytes32", "name": "x1", "type": "bytes32"},
            {"internalType": "bytes32", "name": "y1", "type": "bytes32"},
            {"internalType": "bytes32", "name": "s", "type": "bytes32"},
        ],
        "name": "ecmul",
        "outputs": [
            {"interalType": "bytes32", "name": "x", "type": "bytes32"},
            {"interalType": "bytes32", "name": "y", "type": "bytes32"},
        ],
        "selector": "0x6596c926",
        "signature": "ecmul(bytes32,bytes32,bytes32)",
        "stateMutability": "pure",
    },
    # ecpairing
    "0x0000000000000000000000000000000000000008": {
        "inputs": [
            {"internalType": "bytes32", "name": "x1", "type": "bytes32"},
            {"internalType": "bytes32", "name": "y1", "type": "bytes32"},
            {"internalType": "bytes32", "name": "x2", "type": "bytes32"},
            {"internalType": "bytes32", "name": "y2", "type": "bytes32"},
            {"internalType": "bytes32", "name": "x3", "type": "bytes32"},
            {"internalType": "bytes32", "name": "y3", "type": "bytes32"},
        ],
        "name": "ecpairing",
        "outputs": [{"interalType": "bytes32", "name": "success", "type": "bytes32"}],
        "selector": "0xc9744441",
        "signature": "ecpairing(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)",
        "stateMutability": "pure",
    },
    # blake2f
    # NOTE: These types are not technically correct, but precompiled functions do not actually have a proper abi
    "0x0000000000000000000000000000000000000009": {
        "inputs": [
            {"internalType": "uint32", "name": "rounds", "type": "uint32"},
            {"internalType": "bytes64", "name": "h", "type": "bytes64"},
            {"internalType": "bytes128", "name": "m", "type": "bytes128"},
            {"internalType": "bytes16", "name": "t", "type": "bytes16"},
            {"internalType": "bytes1", "name": "f", "type": "bytes1"},
        ],
        "name": "blake2f",
        "outputs": [{"internalType": "bytes64", "name": "h", "type": "bytes64"}],
        "selector": "0x5cd8a5b3",
        "signature": "blake2f(uint32,bytes64,bytes128,bytes16,bytes1)",
        "stateMutability": "pure",
    },
    # validateTendermintHeader (BNB Chain)
    # ABI reverse engineered from https://github.com/bnb-chain/bsc-genesis-contract/blob/master/contracts/TendermintLightClient.sol
    "0x0000000000000000000000000000000000000100": {
        "inputs": [
            {"internalType": "uint256", "name": "length", "type": "uint256"},
            {"internalType": "uint256", "name": "chainID", "type": "uint256"},
            {"internalType": "uint64", "name": "height", "type": "uint64"},
            {"internalType": "bytes32", "name": "appHash", "type": "bytes32"},
            {
                "internalType": "bytes32",
                "name": "curValidatorSetHash",
                "type": "bytes32",
            },
            {"internalType": "bytes", "name": "nextValidatorSet", "type": "bytes"},
            {"internalType": "bytes", "name": "header", "type": "bytes"},
        ],
        "name": "validateTendermintHeader",
        "outputs": [
            {"internalType": "bytes32[128]", "name": "result", "type": "bytes32[128]"}
        ],
        "selector": "0x26507b88",
        "signature": "validateTendermintHeader(uint256,uint256,uint64,bytes32,bytes32,bytes,bytes)",
        "stateMutability": "pure",
    },
    # verifyMerkleProof (BNB Chain)
    # ABI reverse engineered from https://github.com/bnb-chain/bsc-genesis-contract/blob/master/contracts/MerkleProof.sol
    "0x0000000000000000000000000000000000000101": {
        "inputs": [
            {"internalType": "string", "name": "storeName", "type": "string"},
            {"internalType": "uint256", "name": "keyLength", "type": "uint256"},
            {"internalType": "bytes", "name": "key", "type": "bytes"},
            {"internalType": "uint256", "name": "valueLength", "type": "uint256"},
            {"internalType": "bytes", "name": "value", "type": "bytes"},
            {"internalType": "bytes32", "name": "appHash", "type": "bytes32"},
            {"internalType": "bytes", "name": "proof", "type": "bytes"},
        ],
        "name": "verifyMerkleProof",
        "outputs": [{"internalType": "uint256", "name": "result", "type": "uint256"}],
        "selector": "0x493e017d",
        "signature": "verifyMerkleProof(string,uint256,bytes,uint256,bytes,bytes32,bytes)",
        "stateMutability": "pure",
    },
    # verifyBLSSignature (BNB Chain)
    # ABI reverse engineered from https://github.com/bnb-chain/bsc-genesis-contract/blob/master/contracts/SlashIndicator.sol
    "0x0000000000000000000000000000000000000102": {
        "inputs": [
            {"internalType": "bytes32", "name": "vote", "type": "bytes32"},
            {"internalType": "bytes", "name": "voteSignature", "type": "bytes"},
            {"internalType": "bytes", "name": "voteAddress", "type": "bytes"},
        ],
        "name": "verifyBLSSignature",
        "outputs": [{"internalType": "uint256", "name": "output", "type": "bytes1"}],
        "selector": "0xb470122c",
        "signature": "verifyBLSSignature(bytes32,bytes,bytes)",
        "stateMutability": "pure",
    },
    # BFTLightBlockValidate (BNB Chain)
    # Defined in https://github.com/bnb-chain/BEPs/blob/master/BEP221.md
    "0x0000000000000000000000000000000000000103": {
        "inputs": [
            {
                "internalType": "uint256",
                "name": "consensusStateLength",
                "type": "uint256",
            },
            {"internalType": "bytes", "name": "consensusState", "type": "bytes"},
            {"internalType": "bytes", "name": "lightBlock", "type": "bytes"},
        ],
        "name": "BFTLightBlockValidate",
        "outputs": [
            {"internalType": "bytes", "name": "result", "type": "bytes"}
            # Output is encoded in the following format
            # Value: | validatorSetChanged | empty    | consensusStateLength | newConsensusState          |
            # Size : | 1 byte              | 23 bytes | 8 bytes              | consensusStateLength bytes |
        ],
        "selector": "0xa391fe87",
        "signature": "BFTLightBlockValidate(uint256,bytes,bytes)",
        "stateMutability": "pure",
    },
}


# Map each address to its abi
PRECOMPILED_MAP = {
    hex_to_bytes(address): [
        method | {"selector": hex_to_bytes(method["selector"])} for method in abi
    ]
    if isinstance(abi, list)
    else abi | {"selector": hex_to_bytes(abi["selector"])}
    for address, abi in PRECOMPILES.items()
}
