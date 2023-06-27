#!/usr/bin/env python3

import pytest

from pysad.decoder import ABIDecoder, SignatureDecoder
from pysad.errors import UnknownABI
from pysad.precompiled import decode_precompiled

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
    ],
)
def test_precompiled(address: str, calldata: str, expected: dict):
    assert expected == decode_precompiled(address, calldata)
