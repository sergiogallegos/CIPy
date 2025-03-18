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

"""Custom data types for CIP communication in Pycomm3."""

from __future__ import annotations
import ipaddress
from io import BytesIO
from typing import Any, Dict, Set, Tuple, Type, Union

from .cip import (
    DataType,
    DerivedDataType,
    Struct,
    UINT,
    USINT,
    DWORD,
    UDINT,
    SHORT_STRING,
    n_bytes,
    StructType,
    StringDataType,
    PRODUCT_TYPES,
    VENDORS,
    INT,
    ULINT,
)
from .cip.data_types import _StructReprMeta

__all__ = [
    "IPAddress",
    "ModuleIdentityObject",
    "ListIdentityObject",
    "StructTemplateAttributes",
    "FixedSizeString",
    "Revision",
    "StructTag",
]


def FixedSizeString(size: int, len_type: Union[DataType, Type[DataType]] = UDINT) -> Type[StringDataType]:
    """Create a custom fixed-size string data type.

    Args:
        size: Fixed length of the string in bytes.
        len_type: Data type for encoding the length (default: UDINT).

    Returns:
        Type[StringDataType]: A custom string type class.

    Example:
        >>> MyString = FixedSizeString(10)
        >>> MyString.encode("test")
        b'\x04\x00\x00\x00test\x00\x00\x00\x00\x00\x00'
    """

    class FixedSizeString(StringDataType):
        # Properly bind the outer scope variables as class attributes
        _size = size
        _len_type = len_type

        @classmethod
        def _encode(cls, value: str, *args: Any, **kwargs: Any) -> bytes:
            encoded = value.encode(cls.encoding)
            if len(encoded) > cls._size:
                raise ValueError(f"String length {len(encoded)} exceeds fixed size {cls._size}")
            return cls._len_type.encode(len(value)) + encoded + b"\x00" * (cls._size - len(encoded))

        @classmethod
        def _decode(cls, stream: BytesIO) -> str:
            _len = cls._len_type.decode(stream)
            if _len > cls._size:
                raise ValueError(f"Decoded length {_len} exceeds fixed size {cls._size}")
            _data = cls._stream_read(stream, cls._size)[:_len]
            return _data.decode(cls.encoding)

    return FixedSizeString


class IPAddress(DerivedDataType):
    """IPv4 address data type."""

    @classmethod
    def _encode(cls, value: str) -> bytes:
        """Encode an IPv4 address string to bytes."""
        return ipaddress.IPv4Address(value).packed

    @classmethod
    def _decode(cls, stream: BytesIO) -> str:
        """Decode bytes to an IPv4 address string."""
        return ipaddress.IPv4Address(cls._stream_read(stream, 4)).exploded


class Revision(Struct(USINT("major"), USINT("minor"))):
    """Revision data type with major and minor components."""


class ModuleIdentityObject(
    Struct(
        UINT("vendor"),
        UINT("product_type"),
        UINT("product_code"),
        Revision("revision"),
        n_bytes(2, "status"),
        UDINT("serial"),
        SHORT_STRING("product_name"),
    )
):
    """Module identity object for CIP devices."""

    @classmethod
    def _decode(cls, stream: BytesIO) -> Dict[str, Any]:
        values = super()._decode(stream)
        values["product_type"] = PRODUCT_TYPES.get(values["product_type"], "UNKNOWN")
        values["vendor"] = VENDORS.get(values["vendor"], "UNKNOWN")
        values["serial"] = f"{values['serial']:08x}"
        return values

    @classmethod
    def _encode(cls, values: Dict[str, Any]) -> bytes:
        values = values.copy()
        values["product_type"] = PRODUCT_TYPES[values["product_type"]]
        values["vendor"] = VENDORS[values["vendor"]]
        values["serial"] = int.from_bytes(bytes.fromhex(values["serial"]), "big")
        return super()._encode(values)


class ListIdentityObject(
    Struct(
        UINT,
        UINT,
        UINT("encap_protocol_version"),
        INT,
        UINT,
        IPAddress("ip_address"),
        ULINT,
        UINT("vendor"),
        UINT("product_type"),
        UINT("product_code"),
        Revision("revision"),
        n_bytes(2, "status"),
        UDINT("serial"),
        SHORT_STRING("product_name"),
        USINT("state"),
    )
):
    """Identity object for ListIdentity service."""

    @classmethod
    def _decode(cls, stream: BytesIO) -> Dict[str, Any]:
        values = super()._decode(stream)
        values["product_type"] = PRODUCT_TYPES.get(values["product_type"], "UNKNOWN")
        values["vendor"] = VENDORS.get(values["vendor"], "UNKNOWN")
        values["serial"] = f"{values['serial']:08x}"
        return values


StructTemplateAttributes = Struct(
    UINT("count"),
    Struct(UINT("attr_num"), UINT("status"), UDINT("size"))(name="object_definition_size"),
    Struct(UINT("attr_num"), UINT("status"), UDINT("size"))(name="structure_size"),
    Struct(UINT("attr_num"), UINT("status"), UINT("count"))(name="member_count"),
    Struct(UINT("attr_num"), UINT("status"), UINT("handle"))(name="structure_handle"),
)
"""Structure for template attributes in CIP."""


class _StructTagReprMeta(_StructReprMeta):
    def __repr__(cls) -> str:
        members = ", ".join(repr(m) for m in cls.members)
        return f"{cls.__name__}({members}, bool_members={cls.bits!r}, struct_size={cls.size!r})"


def StructTag(
    *members: Tuple[DataType, int],
    bit_members: Dict[str, Tuple[int, int]],
    private_members: Set[str],
    struct_size: int,
) -> Type[StructType]:
    """Create a custom struct tag type with bit-level members.

    Args:
        *members: Tuple of (DataType, offset) for each member.
        bit_members: Dictionary of bit member names to (offset, bit number).
        private_members: Set of member names to exclude from the final value.
        struct_size: Total size of the struct in bytes.

    Returns:
        Type[StructType]: A custom struct type class.
    """
    _members = [x[0] for x in members]
    _offsets_ = {member: offset for (member, offset) in members}
    _struct = Struct(*_members)

    class StructTag(_struct, metaclass=_StructTagReprMeta):
        # Properly bind the outer scope variables as class attributes
        bits = bit_members
        private = private_members
        size = struct_size
        offsets = _offsets_  # Renamed to avoid shadowing confusion

        @classmethod
        def _decode(cls, stream: BytesIO) -> Dict[str, Any]:
            stream = BytesIO(stream.read(cls.size))
            raw = stream.getvalue()
            values = {}
            for member in cls.members:
                offset = cls.offsets[member]  # Use the renamed attribute
                if stream.tell() < offset:
                    stream.read(offset - stream.tell())
                values[member.name] = member.decode(stream)
            for bit_member, (offset, bit) in cls.bits.items():
                values[bit_member] = bool(raw[offset] & (1 << bit))
            return {k: v for k, v in values.items() if k not in cls.private}

        @classmethod
        def _encode(cls, values: Dict[str, Any]) -> bytes:
            values = values.copy()
            value = bytearray(cls.size)
            for member in cls.members:
                if member.name in cls.private:
                    continue
                offset = cls.offsets[member]  # Use the renamed attribute
                encoded = member.encode(values[member.name])
                value[offset:offset + len(encoded)] = encoded
            for bit_member, (offset, bit) in cls.bits.items():
                if values[bit_member]:
                    value[offset] |= 1 << bit
                else:
                    value[offset] &= ~(1 << bit)
            return bytes(value)

    return StructTag