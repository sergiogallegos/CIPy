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

"""Tag class for representing CIP operation results in Pycomm3."""

from typing import Any, NamedTuple, Optional
from reprlib import repr as _r

__all__ = ["Tag"]


class Tag(NamedTuple):
    """Represents the result of a CIP tag operation.

    Attributes:
        tag: Tag name or request identifier.
        value: Value read/written, or None if an error occurred.
        type: Data type of the tag (optional).
        error: Error message if the operation failed (optional).

    Example:
        >>> tag = Tag("MyTag", 42, "INT", None)
        >>> print(tag)
        MyTag, 42, INT, None
    """

    tag: str
    value: Any
    type: Optional[str] = None
    error: Optional[str] = None

    def __bool__(self) -> bool:
        """Check if the tag operation was successful.

        Returns:
            bool: True if value is not None and error is None, False otherwise.
        """
        return self.value is not None and self.error is None

    def __str__(self) -> str:
        """Human-readable string representation."""
        return f"{self.tag}, {_r(self.value)}, {self.type}, {self.error}"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return (
            f"{self.__class__.__name__}(tag={self.tag!r}, value={self.value!r}, "
            f"type={self.type!r}, error={self.error!r})"
        )