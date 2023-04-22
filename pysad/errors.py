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
