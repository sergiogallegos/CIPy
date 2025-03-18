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

"""Enum-like mapping utility for Pycomm3."""

from typing import Any, Dict, List

__all__ = ["EnumMap"]


def _default_value_key(value: Any) -> Any:
    """Default key function for value mapping."""
    return value


class MapMeta(type):
    """Metaclass for creating enum-like mappings."""

    def __new__(cls, name: str, bases: tuple, classdict: Dict[str, Any]) -> type:
        enumcls = super().__new__(cls, name, bases, classdict)
        members = {
            key: value
            for key, value in classdict.items()
            if not key.startswith("_") and not isinstance(value, (classmethod, staticmethod))
        }
        lower_members = {
            key.lower(): value
            for key, value in members.items()
            if key.lower() not in members
        }
        value_map = (
            {enumcls._value_key_(value): key.lower() for key, value in members.items()}
            if enumcls.__dict__.get("_bidirectional_", True)
            else {}
        )
        enumcls._members_ = {**members, **lower_members, **value_map}  # type: ignore[attr-defined]
        enumcls._attributes = list(members)  # type: ignore[attr-defined]
        enumcls._return_caps_only_ = enumcls.__dict__.get("_return_caps_only_")  # type: ignore[attr-defined]
        return enumcls

    def __getitem__(cls, item: Any) -> Any:
        val = cls._members_[_key(item)]
        return val.upper() if cls._return_caps_only_ and isinstance(val, str) else val

    def get(cls, item: Any, default: Any = None) -> Any:
        val = cls._members_.get(_key(item), default)
        return val.upper() if cls._return_caps_only_ and isinstance(val, str) else val

    def __contains__(cls, item: Any) -> bool:
        return _key(item) in cls._members_

    @property
    def attributes(cls) -> List[str]:
        return cls._attributes


def _key(item: Any) -> Any:
    """Convert item to a lookup key."""
    return item.lower() if isinstance(item, str) else item


class EnumMap(metaclass=MapMeta):
    """Enum-like class with dict-like lookups.

    Provides case-insensitive and bidirectional access to attributes.

    Example:
        >>> class TestEnum(EnumMap):
        ...     x = 100
        >>> TestEnum.x
        100
        >>> TestEnum['X']
        100
        >>> TestEnum[100]
        'x'

    Note:
        Intended for internal use with simple attribute-based subclasses.
    """