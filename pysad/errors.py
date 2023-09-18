#!/usr/bin/env python3


class PySADError(Exception):
    pass


class MismatchedABI(PySADError):
    pass


class BinaryDataError(PySADError):
    pass


class DecodingError(PySADError):
    pass


class UnknownABI(PySADError):
    pass


class InvalidSignature(PySADError):
    pass


class UnknownPrecompile(PySADError):
    def __init__(self, address: bytes | str, selector: bytes | str):
        if isinstance(address, (bytes, bytearray, memoryview)):
            address = "0x" + address.hex()
        if isinstance(selector, (bytes, bytearray, memoryview)):
            selector = "0x" + selector.hex()
        super().__init__(address, selector)
