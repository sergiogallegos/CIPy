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

"""Utility functions for Pycomm3."""

from typing import Tuple, Iterator

__all__ = ["strip_array", "get_array_index", "cycle"]


def strip_array(tag: str) -> str:
    """Strip the array portion from a tag name.

    Args:
        tag: Tag name (e.g., "tag[100]").

    Returns:
        str: Tag name without array portion (e.g., "tag").

    Example:
        >>> strip_array("tag[100]")
        'tag'
    """
    return tag[:tag.find("[")] if "[" in tag else tag


def get_array_index(tag: str) -> Tuple[str, Optional[int]]:
    """Extract tag name and array index from a 1D tag request.

    Args:
        tag: Tag name with optional array index (e.g., "tag[100]").

    Returns:
        Tuple[str, Optional[int]]: Tag name and array index (or None if no index).

    Example:
        >>> get_array_index("tag[100]")
        ('tag', 100)
        >>> get_array_index("tag")
        ('tag', None)
    """
    if tag.endswith("]") and "[" in tag:
        tag, idx_str = tag.rsplit("[", maxsplit=1)
        return tag, int(idx_str[:-1])
    return tag, None


def cycle(stop: int, start: int = 0) -> Iterator[int]:
    """Create an infinite iterator cycling from start to stop.

    Args:
        stop: Upper bound (exclusive).
        start: Starting value (default: 0).

    Returns:
        Iterator[int]: Infinite iterator of integers.

    Example:
        >>> c = cycle(3)
        >>> [next(c) for _ in range(5)]
        [0, 1, 2, 0, 1]
    """
    val = start
    while True:
        if val >= stop:
            val = start
        yield val
        val += 1