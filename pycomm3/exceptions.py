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

"""Exception classes for Pycomm3."""

__all__ = [
    "PycommError",
    "CommError",
    "DataError",
    "BufferEmptyError",
    "ResponseError",
    "RequestError",
]


class PycommError(Exception):
    """Base exception for all Pycomm3-related errors.

    Attributes:
        args: Exception arguments.
    """


class CommError(PycommError):
    """Exception for communication-related issues.

    Raised during socket operations, connection failures, or timeouts.
    """


class DataError(PycommError):
    """Exception for data encoding/decoding errors.

    Raised when binary data cannot be properly processed.
    """


class BufferEmptyError(DataError):
    """Exception for attempts to decode an empty buffer.

    Raised when a data operation expects content but finds none.
    """


class ResponseError(PycommError):
    """Exception for errors in handling request responses.

    Raised when a CIP response is invalid or unexpected.
    """


class RequestError(PycommError):
    """Exception for errors in building requests or processing user data.

    Raised due to invalid input or malformed request structures.
    """