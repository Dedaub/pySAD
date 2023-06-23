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
    def __init__(self, address: str):
        super().__init__(address)
