# pySAD: Python Simple ABI Decoder

`pysad` is modern lightweight library for decoding `EVM` transactions and logs.

## ABI Decoding

```python
>>> permit2 = ABIDecoder(PERMIT2_ABI)
>>> permit2.decode_function("0x2b67b570000000...")
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
    }


>>> weth = ABIDecoder(WETH_ABI)
>>> weth.decode_event(
        [
            "0xDDF252AD1BE2C89B69C2B068FC378DAA952BA7F163C4A11628F55A4DF523B3EF",
            "0x000000000000000000000000EB093C39FC8DED8C4D043C367D4BD75321E8A7C6",
            "0x00000000000000000000000068B3465833FB72A70ECDF485E0E4C7BD8665FC45",
        ],
        "0x0000000000000000000000000000000000000000000000000577F9EFB3EEE9C1"
    )
    {
        "src": "0xeb093c39fc8ded8c4d043c367d4bd75321e8a7c6",
        "dst": "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45",
        "wad": 394058300329486785,
    }
```

## Signature Decoding

```python
>>> signature = SignatureDecoder("transfer(address,uint256)(bool)")
>>> signature.decode_input("0xa9059cbb000...")
    ("0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", 735222617722247178)
>>> signature.decode_output("0x000000000...1")
    (True,)
```

## Decoding Precompiled Functions

`pysad` can also decode calls to precompiled functions.
Supported precompiled functions are
- 0x0...001 to 0x0...009 on the Main Chain
- 0x0...100 to 0x0...103 on the BNB Chain

```python
>>> decode_precompiled("0x00...02", "0x4b263d5cd14b...")
    {
        "data": b"K&=\\\xd1K\xd0\x9a\x92W\xb6.\xbc|\xbd8~\x949S\xd6I]\x07\xf9:v\xc9\xb5\x1c.\xf3\xd1\xe3\xd1\xf92\xed`\x96\xc7\x01\xda\xed@\xd6\xcb\xf4\x8d\x9a/m\x9dn7\n\xa7~8qU\xb4C\x99",
    }
```
