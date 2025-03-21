# -*- coding: utf-8 -*-
#
# Original Copyright (c) 2021 Ian Ottoway <ian@ottoway.dev>
# Original Copyright (c) 2014 Agostino Ruscito <ruscito@gmail.com>
# Modifications Copyright (c) 2025 Sergio Gallegos
#
# This file is part of a fork of the original Pycomm3 project, enhanced in 2025 by Sergio Gallegos.
# Version: 2.0.0
# Changes include modern Python updates, improved documentation, enhanced error handling, and optimized functionality.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

"""Pycomm3: A Python library for communication with Allen-Bradley PLCs via Ethernet/IP.

This module serves as the entry point for the Pycomm3 package, exposing key components
for interacting with PLCs, including drivers, data types, and utilities.

Version: 2.0.0 (2025 fork by Sergio Gallegos)
"""

from ._version import __version__, __version_info__
from .logger import *
from .const import *
from .tag import Tag
from .exceptions import *
from .cip import *
from .custom_types import *
from .cip_driver import *
from .logix_driver import *
from .slc_driver import *

__all__ = [
    "__version__",
    "__version_info__",
    "Tag",
] + logger.__all__ + const.__all__ + exceptions.__all__ + cip.__all__ + custom_types.__all__ + cip_driver.__all__ + logix_driver.__all__ + slc_driver.__all__