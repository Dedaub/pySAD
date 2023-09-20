#!/usr/bin/env python3

import re

from pydantic import ConstrainedStr


class Address(ConstrainedStr):
    regex = re.compile(r"^(0x)?[0-9A-Fa-f]{40}$")
    to_lower = True
