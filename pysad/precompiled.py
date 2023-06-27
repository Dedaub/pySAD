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


def decode_validateTerndermintHeader(abi: dict, calldata: bytes) -> dict[str, Any]:
    """
    Special Case: Decode validateTerndermintHeader function input.
    validateTerndermintHeader is a precompile on the BNB chain.
    function validateTerndermintHeader(length: uint256, chainID: uint256, height: uint64, appHash: bytes32, curValidatorSetHash: bytes32, nextValidatorSet: bytes, header: bytes)
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


# Map each precompiled function to its required decoder function
SPECIAL_CASES = {
    "sha256": decode_single_input,
    "ripemd160": decode_single_input,
    "identity": decode_single_input,
    "modexp": decode_modexp,
    "blake2f": decode_blake2f,
    "validateTerndermintHeader": decode_validateTerndermintHeader,
    "verifyMerkleProof": decode_verifyMerkleProof,
    "verifyBLSSignature": decode_verifyBLSSignature,
}


# Define precompiled function abis
# NOTE: The selectors included have been manually added for conformity. Precompiled functions do not actually have selectors.
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
        "signature": "modexp(uint256,uint256,uint256,bytes,bytes,bytes)",
        "name": "modexp",
        "inputs": [
            {"name": "Bsize", "type": "uint256", "internalType": "uint256"},
            {"name": "Esize", "type": "uint256", "internalType": "uint256"},
            {"name": "Msize", "type": "uint256", "internalType": "uint256"},
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
        "signature": "blake2f(uint32,bytes64,bytes128,bytes16,bytes1)",
        "name": "blake2f",
        "inputs": [
            {"name": "rounds", "type": "uint32", "internalType": "uint32"},
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
    # validateTendermintHeader (BNB Chain)
    # ABI reverse engineered from https://github.com/bnb-chain/bsc-genesis-contract/blob/master/contracts/TendermintLightClient.sol
    {
        "selector": "",
        "signature": "validateTerndermintHeader(uint256,uint256,uint64,bytes32,bytes32,bytes,bytes)",
        "name": "validateTerndermintHeader",
        "inputs": [
            {"name": "length", "type": "uint256", "internalType": "uint256"},
            {"name": "chainID", "type": "uint256", "internalType": "uint256"},
            {"name": "height", "type": "uint64", "internalType": "uint64"},
            {"name": "appHash", "type": "bytes32", "internalType": "bytes32"},
            {
                "name": "curValidatorSetHash",
                "type": "bytes32",
                "internalType": "bytes32",
            },
            {"name": "nextValidatorSet", "type": "bytes", "internalType": "bytes"},
            {"name": "header", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000100",
        "outputs": [
            {"name": "result", "type": "bytes32[128]", "internalType": "bytes32[128]"},
        ],
        "stateMutability": "pure",
    },
    # verifyMerkleProof (BNB Chain)
    # ABI reverse engineered from https://github.com/bnb-chain/bsc-genesis-contract/blob/master/contracts/MerkleProof.sol
    {
        "selector": "0x493e017d",
        "signature": "verifyMerkleProof(string,uint256,bytes,uint256,bytes,bytes32,bytes)",
        "name": "verifyMerkleProof",
        "inputs": [
            {"name": "storeName", "type": "string", "internalType": "string"},
            {"name": "keyLength", "type": "uint256", "internalType": "uint256"},
            {"name": "key", "type": "bytes", "internalType": "bytes"},
            {"name": "valueLength", "type": "uint256", "internalType": "uint256"},
            {"name": "value", "type": "bytes", "internalType": "bytes"},
            {"name": "appHash", "type": "bytes32", "internalType": "bytes32"},
            {"name": "proof", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000101",
        "outputs": [
            {"name": "result", "type": "uint256", "internalType": "uint256"},
        ],
        "stateMutability": "pure",
    },
    # verifyBLSSignature (BNB Chain)
    # ABI reverse engineered from https://github.com/bnb-chain/bsc-genesis-contract/blob/master/contracts/SlashIndicator.sol
    {
        "selector": "0xb470122c",
        "signature": "verifyBLSSignature(bytes32,bytes,bytes)",
        "name": "verifyBLSSignature",
        "inputs": [
            {"name": "vote", "type": "bytes32", "internalType": "bytes32"},
            {"name": "voteSignature", "bytes": "uint256", "internalType": "bytes"},
            {"name": "voteAddress", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000102",
        "outputs": [
            {"name": "output", "type": "bytes1", "internalType": "uint256"},
        ],
        "stateMutability": "pure",
    },
    # BFTLightBlockValidate (BNB Chain)
    # Defined in https://github.com/bnb-chain/BEPs/blob/master/BEP221.md
    # TODO: UPDATE THIS ABI
    {
        "selector": "",
        "signature": "BFTLightBlockValidate()",
        "name": "BFTLightBlockValidate",
        "inputs": [
            {"name": "storeName", "type": "string", "internalType": "string"},
            {"name": "keyLength", "type": "uint256", "internalType": "uint256"},
            {"name": "key", "type": "bytes", "internalType": "bytes"},
            {"name": "valueLength", "type": "uint256", "internalType": "uint256"},
            {"name": "value", "type": "bytes", "internalType": "bytes"},
            {"name": "appHash", "type": "bytes32", "internalType": "bytes32"},
            {"name": "proof", "type": "bytes", "internalType": "bytes"},
        ],
        "address": "0x0000000000000000000000000000000000000103",
        "outputs": [
            {"name": "result", "type": "uint256", "internalType": "uint256"},
        ],
        "stateMutability": "pure",
    },
]


# Map each address to its abi
PRECOMPILED_MAP = {hex_to_bytes(abi["address"]): abi for abi in PRECOMPILES}
