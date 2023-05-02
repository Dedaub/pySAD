#!/usr/bin/env python3

from typing import Literal

SelectorABIMapping = dict[bytes, dict]
ABITypes = Literal["function", "error", "event", "constructor"]
