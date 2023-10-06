#!/usr/bin/env python3

import pytest
from pysad.decoder import ABIDecoder, SignatureDecoder
from pysad.errors import UnknownABI
from pysad.precompiled import decode_precompiled, decode_precompiled_event

from .abis import (
    PERMIT2_ABI,
    PERMIT2_BYTECODE,
    PERMIT2_CREATE,
    UNIVERSAL_ROUTER_ABI,
    UNIVERSAL_ROUTER_BYTECODE,
    UNIVERSAL_ROUTER_CREATE,
    WETH_ABI,
)


@pytest.mark.parametrize(
    "abi,calldata,expected",
    [
        (
            PERMIT2_ABI,
            "2b67b57000000000000000000000000062ff24067cb34156e45eca5133a7ace2fecbe5250000000000000000000000005026f006b85729a8b14553fae6af249ad16c9aab000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006478a9830000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef1c6e67703c7bd7107eed8303fbe6ec2554bf6b000000000000000000000000000000000000000000000000000000006451238b0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000004150b69139c84457a21b5c6c90385b0483077953e067494309a0ac54e5f107594166d881a158e05a505f96d2cd30afb57d32ade18d4103f5c06249ea3e1d47d75a1c00000000000000000000000000000000000000000000000000000000000000",
            {
                "owner": "0x62ff24067cb34156e45eca5133a7ace2fecbe525",
                "permitSingle": {
                    "details": {
                        "token": "0x5026f006b85729a8b14553fae6af249ad16c9aab",
                        "amount": 1461501637330902918203684832716283019655932542975,
                        "expiration": 1685629315,
                        "nonce": 0,
                    },
                    "spender": "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b",
                    "sigDeadline": 1683039115,
                },
                "signature": b"P\xb6\x919\xc8DW\xa2\x1b\\l\x908[\x04\x83\x07yS\xe0gIC\t\xa0\xacT\xe5\xf1\x07YAf\xd8\x81\xa1X\xe0ZP_\x96\xd2\xcd0\xaf\xb5}2\xad\xe1\x8dA\x03\xf5\xc0bI\xea>\x1dG\xd7Z\x1c",
            },
        ),
        (
            PERMIT2_ABI,
            "36c785160000000000000000000000004752747126e7cd1a7cc235fd7baddc9fbc60b9050000000000000000000000004b5ab61593a2401b1075b90c04cbcdd3f87ce01100000000000000000000000000000000000000000000200a260eeaf7fe5a2c19000000000000000000000000f4d2888d29d722226fafa5d9b24f9164c092421e",
            {
                "from": "0x4752747126e7cd1a7cc235fd7baddc9fbc60b905",
                "to": "0x4b5ab61593a2401b1075b90c04cbcdd3f87ce011",
                "amount": 151302937280139702709273,
                "token": "0xf4d2888d29d722226fafa5d9b24f9164c092421e",
            },
        ),
        (
            PERMIT2_ABI,
            "36c785160000000000000000000000004752747126e7cd1a7cc235fd7baddc9fbc60b905000000000000000000000000dc00ba87cc2d99468f7f34bc04cbf72e111a32f7000000000000000000000000000000000000000000000aae0cafa3a7ff736408000000000000000000000000f4d2888d29d722226fafa5d9b24f9164c092421e",
            {
                "from": "0x4752747126e7cd1a7cc235fd7baddc9fbc60b905",
                "to": "0xdc00ba87cc2d99468f7f34bc04cbf72e111a32f7",
                "amount": 50434312426713234236424,
                "token": "0xf4d2888d29d722226fafa5d9b24f9164c092421e",
            },
        ),
        (
            PERMIT2_ABI,
            "2b67b5700000000000000000000000004752747126e7cd1a7cc235fd7baddc9fbc60b905000000000000000000000000f4d2888d29d722226fafa5d9b24f9164c092421e000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006478a98e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef1c6e67703c7bd7107eed8303fbe6ec2554bf6b000000000000000000000000000000000000000000000000000000006451239600000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000041810d604ae0a823c22ecf25846b607ad3e6ebfc3e68f23a3864153161a984d9c82e7f7bcfe6f6a94475597175c6106148120ae71d9ffc529d96f2752bb0d8f6e71c00000000000000000000000000000000000000000000000000000000000000",
            {
                "owner": "0x4752747126e7cd1a7cc235fd7baddc9fbc60b905",
                "permitSingle": {
                    "details": {
                        "token": "0xf4d2888d29d722226fafa5d9b24f9164c092421e",
                        "amount": 1461501637330902918203684832716283019655932542975,
                        "expiration": 1685629326,
                        "nonce": 0,
                    },
                    "spender": "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b",
                    "sigDeadline": 1683039126,
                },
                "signature": b"\x81\r`J\xe0\xa8#\xc2.\xcf%\x84k`z\xd3\xe6\xeb\xfc>h\xf2:8d\x151a\xa9\x84\xd9\xc8.\x7f{\xcf\xe6\xf6\xa9DuYqu\xc6\x10aH\x12\n\xe7\x1d\x9f\xfcR\x9d\x96\xf2u+\xb0\xd8\xf6\xe7\x1c",
            },
        ),
        (
            PERMIT2_ABI,
            "36c78516000000000000000000000000727e41fbd400d1d1c97b449341f0cde62732f9f9000000000000000000000000af06e7c7170eb22d52eb09b5ec5d1373c34164e90000000000000000000000000000000000000000110ce1f377df85e5069ae8b2000000000000000000000000b69753c06bb5c366be51e73bfc0cc2e3dc07e371",
            {
                "from": "0x727e41fbd400d1d1c97b449341f0cde62732f9f9",
                "to": "0xaf06e7c7170eb22d52eb09b5ec5d1373c34164e9",
                "amount": 5276819300453467129036597426,
                "token": "0xb69753c06bb5c366be51e73bfc0cc2e3dc07e371",
            },
        ),
        (
            PERMIT2_ABI,
            "2b67b570000000000000000000000000727e41fbd400d1d1c97b449341f0cde62732f9f9000000000000000000000000b69753c06bb5c366be51e73bfc0cc2e3dc07e371000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006478a9510000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef1c6e67703c7bd7107eed8303fbe6ec2554bf6b000000000000000000000000000000000000000000000000000000006451235900000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000041d0afa6cef78a0cc3255d149ec5cc8ec644819e7540ed34e9e464e8458d4d933803067a20e760a24f368784780e7484e38c8e08412a41371cbd25acfbee387f141b00000000000000000000000000000000000000000000000000000000000000",
            {
                "owner": "0x727e41fbd400d1d1c97b449341f0cde62732f9f9",
                "permitSingle": {
                    "details": {
                        "token": "0xb69753c06bb5c366be51e73bfc0cc2e3dc07e371",
                        "amount": 1461501637330902918203684832716283019655932542975,
                        "expiration": 1685629265,
                        "nonce": 0,
                    },
                    "spender": "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b",
                    "sigDeadline": 1683039065,
                },
                "signature": b"\xd0\xaf\xa6\xce\xf7\x8a\x0c\xc3%]\x14\x9e\xc5\xcc\x8e\xc6D\x81\x9eu@\xed4\xe9\xe4d\xe8E\x8dM\x938\x03\x06z \xe7`\xa2O6\x87\x84x\x0et\x84\xe3\x8c\x8e\x08A*A7\x1c\xbd%\xac\xfb\xee8\x7f\x14\x1b",
            },
        ),
        (
            PERMIT2_ABI,
            "36c7851600000000000000000000000087af91888eaf9ed56c8214a240935836667ad7760000000000000000000000004ff4c7c8754127cc097910cf9d80400adef5b65d000000000000000000000000000000000000000000c8ce6311fc34b4cc081d3d000000000000000000000000e0a458bf4acf353cb45e211281a334bb1d837885",
            {
                "from": "0x87af91888eaf9ed56c8214a240935836667ad776",
                "to": "0x4ff4c7c8754127cc097910cf9d80400adef5b65d",
                "amount": 242759798942029022998568253,
                "token": "0xe0a458bf4acf353cb45e211281a334bb1d837885",
            },
        ),
        (
            PERMIT2_ABI,
            "2b67b57000000000000000000000000087af91888eaf9ed56c8214a240935836667ad776000000000000000000000000e0a458bf4acf353cb45e211281a334bb1d837885000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000006478a8dc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef1c6e67703c7bd7107eed8303fbe6ec2554bf6b00000000000000000000000000000000000000000000000000000000645122e400000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000041325af6413f4d8c7bd4c32a1b9ca01242f6442ab92a373ee1070e1e8fe831fdb94cebd0375c05cecffd4e3c58a34561409f69f3192e8fc6cad982ac7deb9094dd1c00000000000000000000000000000000000000000000000000000000000000",
            {
                "owner": "0x87af91888eaf9ed56c8214a240935836667ad776",
                "permitSingle": {
                    "details": {
                        "token": "0xe0a458bf4acf353cb45e211281a334bb1d837885",
                        "amount": 1461501637330902918203684832716283019655932542975,
                        "expiration": 1685629148,
                        "nonce": 0,
                    },
                    "spender": "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b",
                    "sigDeadline": 1683038948,
                },
                "signature": b"2Z\xf6A?M\x8c{\xd4\xc3*\x1b\x9c\xa0\x12B\xf6D*\xb9*7>\xe1\x07\x0e\x1e\x8f\xe81\xfd\xb9L\xeb\xd07\\\x05\xce\xcf\xfdN<X\xa3Ea@\x9fi\xf3\x19.\x8f\xc6\xca\xd9\x82\xac}\xeb\x90\x94\xdd\x1c",
            },
        ),
    ],
)
def test_function(abi: list[dict], calldata: str, expected: dict):
    contract = ABIDecoder(abi)
    assert expected == contract.decode_function(calldata)


@pytest.mark.parametrize(
    "abi,calldata,bytecode,expected",
    [
        (
            UNIVERSAL_ROUTER_ABI,
            UNIVERSAL_ROUTER_CREATE,
            UNIVERSAL_ROUTER_BYTECODE,
            {
                "params": {
                    "permit2": "0x000000000022d473030f116ddee9f6b43ac78ba3",
                    "weth9": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
                    "seaport": "0x00000000006c3852cbef3e08e8df289169ede581",
                    "nftxZap": "0x0fc584529a2aefa997697fafacba5831fac0c22d",
                    "x2y2": "0x74312363e45dcaba76c59ec49a7aa8a65a67eed3",
                    "foundation": "0xcda72070e455bb31c7690a170224ce43623d0b6f",
                    "sudoswap": "0x2b2e8cda09bba9660dca5cb6233787738ad68329",
                    "nft20Zap": "0xa42f6cada809bcf417deefbdd69c5c5a909249c0",
                    "cryptopunks": "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb",
                    "looksRare": "0x59728544b08ab483533076417fbbb2fd0b17ce3a",
                    "routerRewardsDistributor": "0xea37093ce161f090e443f304e1bf3a8f14d7bb40",
                    "looksRareRewardsDistributor": "0x0554f068365ed43dcc98dcd7fd7a8208a5638c72",
                    "looksRareToken": "0xf4d2888d29d722226fafa5d9b24f9164c092421e",
                    "v2Factory": "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f",
                    "v3Factory": "0x1f98431c8ad98523631ae4a59f267346ea31f984",
                    "pairInitCodeHash": b"\x96\xe8\xacBw\x19\x8f\xf8\xb6\xf7\x85G\x8a\xa9\xa3\x9f@<\xb7h\xdd\x02\xcb\xee2l>}\xa3H\x84_",
                    "poolInitCodeHash": b"\xe3O\x19\x9b\x19\xb2\xb4\xf4\x7fhD&\x19\xd5UR}$Ox\xa3)~\xa8\x93%\xf8C\xf8{\x8bT",
                }
            },
        ),
    ],
)
def test_constructor(abi: list[dict], calldata: str, bytecode: str, expected: dict):
    contract = ABIDecoder(abi)
    assert expected == contract.decode_constructor(calldata, bytecode)


@pytest.mark.parametrize(
    "abi,calldata,bytecode", [(PERMIT2_ABI, PERMIT2_BYTECODE, PERMIT2_CREATE)]
)
def test_missing_constructor(abi: list[dict], calldata: str, bytecode: str):
    with pytest.raises(UnknownABI):
        contract = ABIDecoder(abi)
        contract.decode_constructor(calldata, bytecode)


@pytest.mark.parametrize(
    "signature,input,i_expected,output,o_expected",
    [
        (
            "transfer(address,uint256)(bool)",
            "a9059cbb000000000000000000000000d9e1ce17f2641f24ae83637ab66a2cca9c378b9f0000000000000000000000000000000000000000000000000a340913502ad80a",
            ("0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", 735222617722247178),
            "0x0000000000000000000000000000000000000000000000000000000000000001",
            (True,),
        ),
        (
            "transfer(address,uint256)()",
            "a9059cbb000000000000000000000000d9e1ce17f2641f24ae83637ab66a2cca9c378b9f0000000000000000000000000000000000000000000000000a340913502ad80a",
            ("0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", 735222617722247178),
            None,
            None,
        ),
        (
            "transfer(address,uint256)",
            "a9059cbb000000000000000000000000d9e1ce17f2641f24ae83637ab66a2cca9c378b9f0000000000000000000000000000000000000000000000000a340913502ad80a",
            ("0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", 735222617722247178),
            None,
            None,
        ),
    ],
)
def test_signature(
    signature: str,
    input: bytes,
    i_expected: tuple,
    output: bytes | None,
    o_expected: tuple | None,
):
    sig = SignatureDecoder(signature)
    assert i_expected == sig.decode_input(input)
    if output:
        assert o_expected == sig.decode_output(output)


@pytest.mark.parametrize(
    "abi,topics,memory,expected",
    [
        (
            WETH_ABI,
            [
                "0xDDF252AD1BE2C89B69C2B068FC378DAA952BA7F163C4A11628F55A4DF523B3EF",
                "0x000000000000000000000000EB093C39FC8DED8C4D043C367D4BD75321E8A7C6",
                "0x00000000000000000000000068B3465833FB72A70ECDF485E0E4C7BD8665FC45",
            ],
            "0x0000000000000000000000000000000000000000000000000577F9EFB3EEE9C1",
            {
                "src": "0xeb093c39fc8ded8c4d043c367d4bd75321e8a7c6",
                "dst": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
                "wad": 394058300329486785,
            },
        ),
        (
            WETH_ABI,
            [
                "0x7FCF532C15F0A6DB0BD6D0E038BEA71D30D808C7D98CB3BF7268A95BF5081B65",
                "0x00000000000000000000000068B3465833FB72A70ECDF485E0E4C7BD8665FC45",
            ],
            "0x0000000000000000000000000000000000000000000000000577F9EFB3EEE9C1",
            {
                "src": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
                "wad": 394058300329486785,
            },
        ),
        (
            WETH_ABI,
            [
                "0xE1FFFCC4923D04B559F4D29A8BFC6CDA04EB5B0D3C460751C2402C5C5CC9109C",
                "0x00000000000000000000000068B3465833FB72A70ECDF485E0E4C7BD8665FC45",
            ],
            "0x00000000000000000000000000000000000000000000000000B1A2BC2EC50000",
            {
                "dst": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
                "wad": 50000000000000000,
            },
        ),
        (
            WETH_ABI,
            [
                "0xDDF252AD1BE2C89B69C2B068FC378DAA952BA7F163C4A11628F55A4DF523B3EF",
                "0x00000000000000000000000068B3465833FB72A70ECDF485E0E4C7BD8665FC45",
                "0x000000000000000000000000EB093C39FC8DED8C4D043C367D4BD75321E8A7C6",
            ],
            "0x00000000000000000000000000000000000000000000000000B1A2BC2EC50000",
            {
                "src": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
                "dst": "0xeb093c39fc8ded8c4d043c367d4bd75321e8a7c6",
                "wad": 50000000000000000,
            },
        ),
        # NOTE: The below are custom events which have been created solely for the purpose of testing.
        # These have been created with `foundary`. Specifically, `chisel` with tracing enabled.
        (
            [
                {
                    "anonymous": False,
                    "inputs": [
                        {"indexed": True, "name": "test1", "type": "uint256"},
                        {"indexed": False, "name": "test2", "type": "uint256"},
                    ],
                    "name": "NoReference",
                    "type": "event",
                }
            ],
            [
                "0x93f322a0a02f76bc9d247dce9d0d03e00d0a2ce1a92f315f98d84da096886b65",
                "0x000000000000000000000000000000000000000000000000000000000000001a",
            ],
            "0x0000000000000000000000000000000000000000000000000000000000000008",
            {
                "test1": 26,
                "test2": 8,
            },
        ),
        (
            [
                {
                    "anonymous": False,
                    "inputs": [
                        {"indexed": False, "name": "test", "type": "string"},
                    ],
                    "name": "NonIndexedReference",
                    "type": "event",
                }
            ],
            [
                "0x070b4299d78ef388a40cab45a84ef7001a713166afa3267f48da3d63fcb53173",
            ],
            "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c68656c6c6f2c20776f726c640000000000000000000000000000000000000000",
            {"test": "hello, world"},
        ),
        (
            [
                {
                    "anonymous": False,
                    "inputs": [
                        {"indexed": True, "name": "test", "type": "string"},
                    ],
                    "name": "IndexedReference",
                    "type": "event",
                }
            ],
            [
                "0xb5282c73b079f44e2d68c61bc0d431072ac8235ba110b38ab6d468e6ed452ab7",
                "0x29bf7021020ea89dbd91ef52022b5a654b55ed418c9e7aba71ef3b43a51669f2",
            ],
            "0x",
            {
                "test": b"\x29\xbf\x70\x21\x02\x0e\xa8\x9d\xbd\x91\xef\x52\x02\x2b\x5a\x65\x4b\x55\xed\x41\x8c\x9e\x7a\xba\x71\xef\x3b\x43\xa5\x16\x69\xf2"
            },
        ),
        (
            [
                {
                    "anonymous": False,
                    "inputs": [
                        {"indexed": True, "name": "test1", "type": "string"},
                        {"indexed": False, "name": "test2", "type": "string"},
                        {"indexed": False, "name": "test3", "type": "uint256"},
                    ],
                    "name": "MixedReference",
                    "type": "event",
                }
            ],
            [
                "0x596c14f170677e8244dead9999f146cf17f2731114c66d55e5eab65de99b9cdd",
                "0x29bf7021020ea89dbd91ef52022b5a654b55ed418c9e7aba71ef3b43a51669f2",
            ],
            "0x000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000007e7000000000000000000000000000000000000000000000000000000000000000e676f6f646279652c20776f726c64000000000000000000000000000000000000",
            {
                "test1": b"\x29\xbf\x70\x21\x02\x0e\xa8\x9d\xbd\x91\xef\x52\x02\x2b\x5a\x65\x4b\x55\xed\x41\x8c\x9e\x7a\xba\x71\xef\x3b\x43\xa5\x16\x69\xf2",
                "test2": "goodbye, world",
                "test3": 2023,
            },
        ),
    ],
)
def test_event(abi: list[dict], topics: list[str], memory: str, expected: dict):
    contract = ABIDecoder(abi)
    assert expected == contract.decode_event(topics, memory)


@pytest.mark.parametrize(
    "address,calldata,expected",
    [
        (
            "0x0000000000000000000000000000000000000001",
            "e3375d4cf79ac75aca3fdd272bb3ad8e2f3b7802dfd229393f16ee840a04c7bc000000000000000000000000000000000000000000000000000000000000001cb63a63b9163d225916fb761a999a8dfee9b1a68ccd1981bef5dabf3ed93f42d45e42fb96371631f85224ac64fa47f7e7d8d34d4656fb3057235d4dc3e05ab527",
            {
                "hash": b"\xe37]L\xf7\x9a\xc7Z\xca?\xdd'+\xb3\xad\x8e/;x\x02\xdf\xd2)9?\x16\xee\x84\n\x04\xc7\xbc",
                "v": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c",
                "r": b'\xb6:c\xb9\x16="Y\x16\xfbv\x1a\x99\x9a\x8d\xfe\xe9\xb1\xa6\x8c\xcd\x19\x81\xbe\xf5\xda\xbf>\xd9?B\xd4',
                "s": b"^B\xfb\x967\x161\xf8R$\xacd\xfaG\xf7\xe7\xd8\xd3MFV\xfb0W#]M\xc3\xe0Z\xb5'",
            },
        ),
        (
            "0x0000000000000000000000000000000000000002",
            "4b263d5cd14bd09a9257b62ebc7cbd387e943953d6495d07f93a76c9b51c2ef3d1e3d1f932ed6096c701daed40d6cbf48d9a2f6d9d6e370aa77e387155b44399",
            {
                "data": b"K&=\\\xd1K\xd0\x9a\x92W\xb6.\xbc|\xbd8~\x949S\xd6I]\x07\xf9:v\xc9\xb5\x1c.\xf3\xd1\xe3\xd1\xf92\xed`\x96\xc7\x01\xda\xed@\xd6\xcb\xf4\x8d\x9a/m\x9dn7\n\xa7~8qU\xb4C\x99",
            },
        ),
        (
            "0x0000000000000000000000000000000000000003",
            "7046f8cc3d057a214bceef6a90b7e0575d97f0beb30e38553013b5b18bb5fabf16e2d890ecfb89718990fe180cff1fed3d2c72022670ddabf5fd6f1d6b175474e89094c44da98b954eedeac495271d0f0000000000000000000000000000000000000000000000010e9deaaf401e0000",
            {
                "data": b"pF\xf8\xcc=\x05z!K\xce\xefj\x90\xb7\xe0W]\x97\xf0\xbe\xb3\x0e8U0\x13\xb5\xb1\x8b\xb5\xfa\xbf\x16\xe2\xd8\x90\xec\xfb\x89q\x89\x90\xfe\x18\x0c\xff\x1f\xed=,r\x02&p\xdd\xab\xf5\xfdo\x1dk\x17Tt\xe8\x90\x94\xc4M\xa9\x8b\x95N\xed\xea\xc4\x95'\x1d\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x0e\x9d\xea\xaf@\x1e\x00\x00"
            },
        ),
        (
            "0x0000000000000000000000000000000000000004",
            "63c08c1c5f223e7f6a85a0405fb86610fcffd99493bca242a056d7daeed9a8ae7b975b4c4f4be55a1634eb734869bb53825a56932b03c2a961d861485b91e53f",
            {
                "data": b'c\xc0\x8c\x1c_">\x7fj\x85\xa0@_\xb8f\x10\xfc\xff\xd9\x94\x93\xbc\xa2B\xa0V\xd7\xda\xee\xd9\xa8\xae{\x97[LOK\xe5Z\x164\xebsHi\xbbS\x82ZV\x93+\x03\xc2\xa9a\xd8aH[\x91\xe5?'
            },
        ),
        (
            "0x0000000000000000000000000000000000000005",
            "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000200243cc2425278870c85f8e3fd5a160ef36de5f8191fa9c0b2daa3a9136d5acc200000000000000000000000000000000000000000000000000000000004000000800000000000011000000000000000000000000000000000000000000000001",
            {
                "Bsize": 32,
                "Esize": 32,
                "Msize": 32,
                "B": b"\x02C\xcc$%'\x88p\xc8_\x8e?\xd5\xa1`\xef6\xde_\x81\x91\xfa\x9c\x0b-\xaa:\x916\xd5\xac\xc2",
                "E": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00",
                "M": b"\x08\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
            },
        ),
        (
            "0x0000000000000000000000000000000000000006",
            "1a32e48a7f62bf3ad48681d0e961f999deb91ce4cf19187ac65a5198304f0d171c6f08ed884441f5bac2af4d4711c2b90ede9ab1efa527e6ecf9487771aed9362ca56ae478c249640c03c03992e7176daca84395f06ba4a592085498f5f1134f1c26a3bdc037e2a691acd9b7d101cfe199b9c9722af66d096e0ee65817f2cffa",
            {
                "x1": b"\x1a2\xe4\x8a\x7fb\xbf:\xd4\x86\x81\xd0\xe9a\xf9\x99\xde\xb9\x1c\xe4\xcf\x19\x18z\xc6ZQ\x980O\r\x17",
                "y1": b"\x1co\x08\xed\x88DA\xf5\xba\xc2\xafMG\x11\xc2\xb9\x0e\xde\x9a\xb1\xef\xa5'\xe6\xec\xf9Hwq\xae\xd96",
                "x2": b",\xa5j\xe4x\xc2Id\x0c\x03\xc09\x92\xe7\x17m\xac\xa8C\x95\xf0k\xa4\xa5\x92\x08T\x98\xf5\xf1\x13O",
                "y2": b"\x1c&\xa3\xbd\xc07\xe2\xa6\x91\xac\xd9\xb7\xd1\x01\xcf\xe1\x99\xb9\xc9r*\xf6m\tn\x0e\xe6X\x17\xf2\xcf\xfa",
            },
        ),
        (
            "0x0000000000000000000000000000000000000007",
            "1edf3ff76267b56337a2d6665acd03059f33a87cfb00d9a57b668a8795ebdf7316b60c1f4f86d76209faf8c49b02fc9bacf4fbf7da16dc41c0a3886538889f5808856449bdd0699e1b086013fb981ad688793afb881cf6f6f340013436f2fdbb",
            {
                "x1": b"\x1e\xdf?\xf7bg\xb5c7\xa2\xd6fZ\xcd\x03\x05\x9f3\xa8|\xfb\x00\xd9\xa5{f\x8a\x87\x95\xeb\xdfs",
                "y1": b"\x16\xb6\x0c\x1fO\x86\xd7b\t\xfa\xf8\xc4\x9b\x02\xfc\x9b\xac\xf4\xfb\xf7\xda\x16\xdcA\xc0\xa3\x88e8\x88\x9fX",
                "s": b"\x08\x85dI\xbd\xd0i\x9e\x1b\x08`\x13\xfb\x98\x1a\xd6\x88y:\xfb\x88\x1c\xf6\xf6\xf3@\x0146\xf2\xfd\xbb",
            },
        ),
        (
            "0x0000000000000000000000000000000000000008",
            "0556ae33b821fc82408fd5fb3c42709362fd5426f119be69dc05efd11ad7ed65156c5d5a7caa6ca66164d39e66524f082cb15049d3f7d19d76021f42bdbaf831198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa158b227deca4090c40e3b24b23d8681eecdd0da559f7f67d206b29546fee9c551a1d9d88f5cc088fff7dd37c94748a95327e9160cfc021cc7bf209634298bcdf260e01b251f6f1c7e7ff4e580791dee8ea51d87a358e038b4efe30fac09383c10118c4d5b837bcc2bc89b5b398b5974e9f5944073b32078b7e231fec938883b004fc6369f7110fe3d25156c1bb9a72859cf2a04641f99ba4ee413c80da6a5fe422febda3c0c0632a56475b4214e5615e11e6dd3f96e6cea2854a87d4dacc5e55",
            {
                "x1": b"\x05V\xae3\xb8!\xfc\x82@\x8f\xd5\xfb<Bp\x93b\xfdT&\xf1\x19\xbei\xdc\x05\xef\xd1\x1a\xd7\xede",
                "y1": b"\x15l]Z|\xaal\xa6ad\xd3\x9efRO\x08,\xb1PI\xd3\xf7\xd1\x9dv\x02\x1fB\xbd\xba\xf81",
                "x2": b"\x19\x8e\x93\x93\x92\rH:r`\xbf\xb71\xfb]%\xf1\xaaI35\xa9\xe7\x12\x97\xe4\x85\xb7\xae\xf3\x12\xc2",
                "y2": b'\x18\x00\xde\xef\x12\x1f\x1evBj\x00f^\\DygC"\xd4\xf7^\xda\xddF\xde\xbd\\\xd9\x92\xf6\xed',
                "x3": b'\t\x06\x89\xd0X_\xf0u\xec\x9e\x99\xadi\x0c3\x95\xbcK13p\xb3\x8e\xf3U\xac\xda\xdc\xd1"\x97[',
                "y3": b"\x12\xc8^\xa5\xdb\x8cm\xebJ\xabq\x80\x8d\xcb@\x8f\xe3\xd1\xe7i\x0cC\xd3{L\xe6\xcc\x01f\xfa}\xaa",
            },
        ),
        (
            "0x0000000000000000000000000000000000000009",
            "0000000c28c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05ba3d96883efef56e745cdec90cfbd1a2e2b44b1c22b8ec001e5de88b94ae2601485faac16e07b4323c1ddc16f74ed472df38f2e994fdec49dbf5745284f7dea5b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000001",
            {
                "rounds": 12,
                "h": b"(\xc9\xbd\xf2g\xe6\tj;\xa7\xca\x84\x85\xaeg\xbb+\xf8\x94\xfer\xf3n<\xf16\x1d_:\xf5O\xa5\xd1\x82\xe6\xad\x7fR\x0eQ\x1fl>+\x8ch\x05\x9bk\xbdA\xfb\xab\xd9\x83\x1fy!~\x13\x19\xcd\xe0[",
                "m": b"\xa3\xd9h\x83\xef\xefV\xe7E\xcd\xec\x90\xcf\xbd\x1a.+D\xb1\xc2+\x8e\xc0\x01\xe5\xde\x88\xb9J\xe2`\x14\x85\xfa\xac\x16\xe0{C#\xc1\xdd\xc1ot\xedG-\xf3\x8f.\x99O\xde\xc4\x9d\xbfWE(O}\xea[\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "t": b"@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "f": b"\x01",
            },
        ),
        # BNB PRECOMPILES - These test cases were manually created, may not be representative of actual input.
        (
            "0x0000000000000000000000000000000000000100",
            "00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000038000000000000001400000000000000000000000000000000000000000000000000000000000001b5000000000000000000000000000000000000000000000000000000000005045a000000000000000000000000000000000000000000000000000000000005045a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005045a",
            {
                "length": 32,
                "chainID": 56,
                "height": 20,
                "appHash": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xb5",
                "curValidatorSetHash": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x04Z",
                "nextValidatorSet": b"",
                "header": b"\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xb5\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x04Z\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x04Z\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x04Z",
            },
        ),
        (
            "0x0000000000000000000000000000000000000101",
            "0000000000000000000000000000000000000000000048656c6c6f576f726c64000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000000000000005e2b47f000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000025a2977000000000000000000000000000000000000000000000000000020b0b0e7f8b80000000000000000000000000000000000000000000000000000000000000000000000000000000000002db9f3b0d83e5b68",
            {
                "storeName": "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00HelloWorld",
                "keyLength": 40,
                "key": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\xe2\xb4\x7f",
                "valueLength": 20,
                "value": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02Z)w",
                "appHash": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \xb0\xb0\xe7\xf8\xb8",
                "proof": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00-\xb9\xf3\xb0\xd8>[h",
            },
        ),
        (
            "0x0000000000000000000000000000000000000102",
            "000000000000000000000000000000000000000000000000000000001d27a50d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e27ad11ac627c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000103",
            {
                "vote": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d'\xa5\r",
                "voteSignature": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e'\xad\x11\xacb|",
                "voteAddress": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x03",
            },
        ),
        (
            "0x0000000000000000000000000000000000000103",
            "0000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000000000015f9eb5f9800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac447c49f680ed739e15118",
            {
                "consensusStateLength": 40,
                "consensusState": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15\xf9\xeb_\x98",
                "lightBlock": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\n\xc4G\xc4\x9fh\x0e\xd79\xe1Q\x18",
            },
        ),
        # ARB PRECOMPILES - These test cases were manually created, may not be representative of actual input.
        (
            "0x0000000000000000000000000000000000000064",
            b"+@z\x82\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07E\x92t",
            {"arbBlockNum": 121999988},
        ),
        ("0x0000000000000000000000000000000000000064", b"\xa3\xb1\xb3\x1d", {}),
        ("0x0000000000000000000000000000000000000064", b"\xa3\xb1\xb3\x1d", {}),
        ("0x0000000000000000000000000000000000000064", b"\xa3\xb1\xb3\x1d", {}),
        ("0x0000000000000000000000000000000000000064", b"\xa3\xb1\xb3\x1d", {}),
        (
            "0x0000000000000000000000000000000000000066",
            b"\x8a\x18g\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x03\x8d",
            {"index": 909},
        ),
        (
            "0x0000000000000000000000000000000000000066",
            b"D \xe4\x86\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00nR\xbbv"
            b"\x98\x1e\x83\xa5_(q\x08 3c\xff\x1f\xc7\xce@",
            {"addr": "0x6e52bb76981e83a55f287108203363ff1fc7ce40"},
        ),
        (
            "0x0000000000000000000000000000000000000066",
            b"D \xe4\x86\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8c\x16$O"
            b"\xae\xd8T\xaa\x90w\xb1q\x82.\xcc\xec\xeb\x8f\x89c",
            {"addr": "0x8c16244faed854aa9077b171822ecceceb8f8963"},
        ),
        (
            "0x0000000000000000000000000000000000000066",
            b"\x8a\x18g\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\ni\xa7",
            {"index": 682407},
        ),
        (
            "0x0000000000000000000000000000000000000066",
            b"\x8a\x18g\x88\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\nj\x8c",
            {"index": 682636},
        ),
        ("0x000000000000000000000000000000000000006c", b"\xc6\xf7\xde\x0e", {}),
        ("0x000000000000000000000000000000000000006c", b"\xc6\xf7\xde\x0e", {}),
        ("0x000000000000000000000000000000000000006c", b"\xc6\xf7\xde\x0e", {}),
        ("0x000000000000000000000000000000000000006c", b"\xc6\xf7\xde\x0e", {}),
        ("0x000000000000000000000000000000000000006c", b"\xc6\xf7\xde\x0e", {}),
        (
            "0x000000000000000000000000000000000000006e",
            b"\xc9\xf9]2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\xb5n"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\t#U\xfb\xc7\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00@\x89\x8fB-p\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00@\x89\x8fB-p\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x007I\xc4\xf0"
            b"4\x02,9\xec\xaf\xfa\xba\x18%U\xd4P\x8c\xac\xcc\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01`\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00D\xfd1\xc5\xbajs\xf5"\xa3P\xe5^'
            b"0\x9eC~\xaf\xf0\x89\xa1\x8a\xff#\xee<\xda[\x01;\xe1\x95S\xeb\xa7\x83\x86"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x02q\xe7;\xe5hS\x1a\x81\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            {
                "beneficiary": "0x0000000000000000000000000000000000000000",
                "callvalue": 0,
                "deposit": 70959558176112,
                "feeRefundAddress": "0x0000000000000000000000000000000000000000",
                "gasFeeCap": 0,
                "gasLimit": 0,
                "l1BaseFee": 39247543239,
                "maxSubmissionFee": 70959558176112,
                "requestId": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x0f\xb5n",
                "retryData": b'\xfd1\xc5\xbajs\xf5"\xa3P\xe5^0\x9eC~\xaf\xf0\x89\xa1'
                b"\x8a\xff#\xee<\xda[\x01;\xe1\x95S\xeb\xa7\x83\x86"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02q\xe7;\xe5"
                b"hS\x1a\x81",
                "retryTo": "0x3749c4f034022c39ecaffaba182555d4508caccc",
            },
        ),
        (
            "0x000000000000000000000000000000000000006e",
            b"\xed\xa1\x12,\xa0\x97\x17\xb4\xbf\xb7\x0e\x84\x10\t\xab\xb7\xa9\xec\xcfk"
            b"f\xea(G\xe2\x8e\xe8\xb5Q\xe32_\x13\x81Z\xcb",
            {
                "ticketId": b"\xa0\x97\x17\xb4\xbf\xb7\x0e\x84\x10\t\xab\xb7\xa9\xec\xcfk"
                b"f\xea(G\xe2\x8e\xe8\xb5Q\xe32_\x13\x81Z\xcb"
            },
        ),
        (
            "0x000000000000000000000000000000000000006e",
            b"\xc9\xf9]2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\xb5h"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07<\x95h^\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x01\xcaX\x89\x1a\xc3\x80\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x11\xe1\xa3\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0428\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x01\x7fP\x01\xe9\x1b\x80\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\xa1\x8c\xb3M\xb22\xc0"
            b"2\x87;\\\xda\xd11\xec(n\xb0\xbf\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\tg`\xf2\x089\x02Pd\x9e>\x87c4\x8ex:\xefUb\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01`\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01D.V{6\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\xda\xc1\x7f\x95\x8d.\xe5#\xa2 b\x06"
            b"\x99E\x97\xc1=\x83\x1e\xc7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\"
            b"\xda\xd11\xec(n\xb0\xbf\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            b"T\x0b\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            {
                "beneficiary": "0x89a18cb34db232c032873b5cdad131ec286eb0bf",
                "callvalue": 0,
                "deposit": 503956582876032,
                "feeRefundAddress": "0x89a18cb34db232c032873b5cdad131ec286eb0bf",
                "gasFeeCap": 300000000,
                "gasLimit": 275000,
                "l1BaseFee": 31081195614,
                "maxSubmissionFee": 421456582876032,
                "requestId": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x0f\xb5h",
                "retryData": b".V{6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\xda\xc1\x7f\x95\x8d.\xe5#\xa2 b\x06\x99E\x97\xc1"
                b"=\x83\x1e\xc7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x02T\x0b\xe4\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00",
                "retryTo": "0x096760f208390250649e3e8763348e783aef5562",
            },
        ),
        (
            "0x000000000000000000000000000000000000006e",
            b"\xed\xa1\x12,%\x14v\x0c\xd5\x8bYT\xc2 \xa0\x7f|\xa3\xf1\xde\xe5\x13\x98w"
            b"Px\xc2a\x85\xdb\x11\xa5T\x8e\xa3\xb7",
            {
                "ticketId": b"%\x14v\x0c\xd5\x8bYT\xc2 \xa0\x7f|\xa3\xf1\xde\xe5\x13\x98w"
                b"Px\xc2a\x85\xdb\x11\xa5T\x8e\xa3\xb7"
            },
        ),
        (
            "0x000000000000000000000000000000000000006e",
            b"\xc9\xf9]2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0f\xb5d"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07V\x8a_\xcc\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x01\xc7\xbb\x9f<-\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x11\xe1\xa3\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x0428\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01|\xb3\x18\n\x85\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\xa1\x8c\xb3M\xb22\xc0"
            b"2\x87;\\\xda\xd11\xec(n\xb0\xbf\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\tg`\xf2\x089\x02P"
            b"d\x9e>\x87c4\x8ex:\xefUb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x01`\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x01D.V{6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xda\xc1\x7f\x95\x8d.\xe5#\xa2 b\x06\x99E\x97\xc1=\x83\x1e\xc7"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x89\xa1\x8c\xb3M\xb22\xc0"
            b"2\x87;\\\xda\xd11\xec(n\xb0\xbf\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\xd7\x84\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            {
                "beneficiary": "0x89a18cb34db232c032873b5cdad131ec286eb0bf",
                "callvalue": 0,
                "deposit": 501083621043456,
                "feeRefundAddress": "0x89a18cb34db232c032873b5cdad131ec286eb0bf",
                "gasFeeCap": 300000000,
                "gasLimit": 275000,
                "l1BaseFee": 31516680140,
                "maxSubmissionFee": 418583621043456,
                "requestId": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x0f\xb5d",
                "retryData": b".V{6\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\xda\xc1\x7f\x95\x8d.\xe5#\xa2 b\x06\x99E\x97\xc1"
                b"=\x83\x1e\xc7\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x89\xa1\x8c\xb3M\xb22\xc02\x87;\\\xda\xd11\xec(n\xb0\xbf"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x17\xd7\x84\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\xa0\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "retryTo": "0x096760f208390250649e3e8763348e783aef5562",
            },
        ),
    ],
)
def test_precompiled(address: str, calldata: str, expected: dict):
    assert expected == decode_precompiled(address, calldata)


@pytest.mark.parametrize(
    "address,topics,data,expected",
    [
        (
            "0x0000000000000000000000000000000000000064",
            [
                b"\xe9\xe1=\xa3di\x9f\xb5\xb0Io\xf5\xa0\xfcpv\n\xd5\x83n\x93\xba\x96V"
                b"\x8aNB\xb9\x91J\x8b\x95",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"\xf6\xab\xe3z\xca\xbd\x87(\x9bb\x1e\xcf4\x0cj^]p\xd2\xe8\xb1-\xdb1"
                b"o\x0e\xde\x8c\xb0p}~",
                b"\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01d\xd3",
            ],
            b"",
            {
                "hash": b"\xf6\xab\xe3z\xca\xbd\x87(\x9bb\x1e\xcf4\x0cj^]p\xd2\xe8\xb1-\xdb1"
                b"o\x0e\xde\x8c\xb0p}~",
                "position": 6277101735386680763835789423207666416102355444464034604243,
                "reserved": 0,
            },
        ),
        (
            "0x0000000000000000000000000000000000000064",
            [
                b"\xe9\xe1=\xa3di\x9f\xb5\xb0Io\xf5\xa0\xfcpv\n\xd5\x83n\x93\xba\x96V"
                b"\x8aNB\xb9\x91J\x8b\x95",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"=q2\x84|\x10\x93\xcd\xa7\x0f\xf1m~\xd5\xf21\xd7\xf5\xfa}\xca\x8b2\x97"
                b"P\xee\x06P\xb7\\;\x86",
                b"\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01d\xd3",
            ],
            b"",
            {
                "hash": b"=q2\x84|\x10\x93\xcd\xa7\x0f\xf1m~\xd5\xf21\xd7\xf5\xfa}"
                b"\xca\x8b2\x97P\xee\x06P\xb7\\;\x86",
                "position": 12554203470773361527671578846415332832204710888928069117139,
                "reserved": 0,
            },
        ),
        (
            "0x0000000000000000000000000000000000000064",
            [
                b">z\xaf\xa7}\xbf\x18k\x7f\xd4\x88\x00k\xef\xf8\x93tL\xaa<Oo)\x9e"
                b"\x8ap\x9f\xa2\x08st\xfc",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c!\xb1\x80\x13xJ"
                b"\x10{l\x93h\xd8\x1e\x92\xd4\x9b\xdd\x10",
                b"TL\x844\xb1(,\x86sa\xa6\x95e\xb2\xdf\xe7j\xff\xa1\xf2\xfd\xe5\xf7\xbd"
                b"\xd2\xe8\xfe\xe7\x95+g~",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01d\xd3",
            ],
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x0c!\xb1\x80\x13xJ"
            b"\x10{l\x93h\xd8\x1e\x92\xd4\x9b\xdd\x10\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x07\xe4l*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x156\x85\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00e\t\x1cH"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Z\xf3\x10z@\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            {
                "arbBlockNum": 132410410,
                "caller": "0x080c21b18013784a107b6c9368d81e92d49bdd10",
                "callvalue": 100000000000000,
                "data": b"",
                "destination": "0x080c21b18013784a107b6c9368d81e92d49bdd10",
                "ethBlockNum": 18167429,
                "hash": 38129472109009339098803329695558829488324570893626517239820621835663850563454,
                "position": 91347,
                "timestamp": 1695095880,
            },
        ),
        (
            "0x000000000000000000000000000000000000006e",
            [
                b"\\\xcd\x00\x95\x02P\x9c\xf2\x87b\xc6xX\x99M\x85\xb1c\xbbnE\x1f^\x9d"
                b"\xf7\xc5\xe1\x8c\x9c.\x12>",
                b"$\xf3\xab=\xf3\xa1\x96\x85!\xa8\x91\xbb\xf9\xcfX\x1a\x90{6\xf0\xa4\x90Yz"
                b"\x10n-\xb3%h\xe9@",
                b"`\xf8\xda\xb1D\x14\xf5sX\x80\xe6\x07\xca)\xc2\xf7x\xd2\x8b~1\xbbb7sEU\x03"
                b"\x97\x15J\xee",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\xba\x19"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80B\x0b2\x16\xe8~N"
            b"\xd2T\x89\xef9)\x01\xaa\xfc\x10\x95\x1b\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            {
                "donatedGas": 178713,
                "gasDonor": "0x80420b3216e87e4ed25489ef392901aafc10951b",
                "maxRefund": 115792089237316195423570985008687907853269984665640564039457584007913129639935,
                "retryTxHash": b"`\xf8\xda\xb1D\x14\xf5sX\x80\xe6\x07\xca)\xc2\xf7x\xd2\x8b~"
                b"1\xbbb7sEU\x03\x97\x15J\xee",
                "sequenceNum": 0,
                "submissionFeeRefund": 0,
                "ticketId": b"$\xf3\xab=\xf3\xa1\x96\x85!\xa8\x91\xbb\xf9\xcfX\x1a\x90{6\xf0"
                b"\xa4\x90Yz\x10n-\xb3%h\xe9@",
            },
        ),
        (
            "0x000000000000000000000000000000000000006e",
            [
                b"|y<\xce\xd5t=\xc5\xf51\xbb\xe2\xbf\xb5\xa9\xfa?@\xad\xef)#\x1ej"
                b"\xb1e\xc0\x8a)\xe3\xdd\x89",
                b"\x941\xe7\x02\xb7}j\x01\x8e\x01\xa5E\x97\xbd\x85\xc6\xd3\xeah\x0f"
                b"'\x81\x16Q\xc5\xba\x7f\xb1\x1d\xffV\x93",
            ],
            b"",
            {
                "ticketId": b"\x941\xe7\x02\xb7}j\x01\x8e\x01\xa5E\x97\xbd\x85\xc6"
                b"\xd3\xeah\x0f'\x81\x16Q\xc5\xba\x7f\xb1\x1d\xffV\x93"
            },
        ),
        (
            "0x000000000000000000000000000000000000006e",
            [
                b"\\\xcd\x00\x95\x02P\x9c\xf2\x87b\xc6xX\x99M\x85\xb1c\xbbnE\x1f^\x9d"
                b"\xf7\xc5\xe1\x8c\x9c.\x12>",
                b"\x941\xe7\x02\xb7}j\x01\x8e\x01\xa5E\x97\xbd\x85\xc6\xd3\xeah\x0f"
                b"'\x81\x16Q\xc5\xba\x7f\xb1\x1d\xffV\x93",
                b"U\xea\n\xd4\x19{U\x1aX\xd7\x05\xb6p\xcb\xc8\xa0\xa0\xf4\xd0\xa3\xb2<e\x86"
                b"\x85\xc6\x02\xe3EzN\xbf",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\\'\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00sM\xc7\x07\xccQN\x11\xdc\xe4\xaf4\xe7kD\x0e"
            b"\xfc\x14\xb1\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00=\x89"
            b"\xdb\xef\x9c\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x005n\xb5\x9eU\xc0",
            {
                "donatedGas": 89127,
                "gasDonor": "0x734dc707cc514e11dce4af34e76b440efc14b105",
                "maxRefund": 67662309727424,
                "retryTxHash": b"U\xea\n\xd4\x19{U\x1aX\xd7\x05\xb6p\xcb\xc8\xa0"
                b"\xa0\xf4\xd0\xa3\xb2<e\x86\x85\xc6\x02\xe3EzN\xbf",
                "sequenceNum": 0,
                "submissionFeeRefund": 58749609727424,
                "ticketId": b"\x941\xe7\x02\xb7}j\x01\x8e\x01\xa5E\x97\xbd\x85\xc6"
                b"\xd3\xeah\x0f'\x81\x16Q\xc5\xba\x7f\xb1\x1d\xffV\x93",
            },
        ),
        (
            "0x0000000000000000000000000000000000000070",
            [
                b"<\x9ejw'U@s\x11\xe3\xb3[>\xe5g\x99\xdf\x8f\x879YA\xb3\xa6X\xee\xe9\xe0"
                b"\x8ag\xeb\xda",
                b"\xe3\x88\xb3\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd3E\xe4\x1a\xe2\xcb\x001"
                b"\x19V\xaaq\t\xfc\x80\x1a\xe8\xc8\x1aR",
            ],
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 "
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00D"
            b"\xe3\x88\xb3\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x9c\xc00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            {
                "data": b"\xe3\x88\xb3\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"c\x9c\xc00",
                "method": b"\xe3\x88\xb3\x81",
                "owner": "0xd345e41ae2cb00311956aa7109fc801ae8c81a52",
            },
        ),
    ],
)
def test_precompiled_event(
    address: str, topics: list[bytes], data: bytes, expected: dict
):
    assert expected == decode_precompiled_event(address, topics, data)
