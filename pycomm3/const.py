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

"""Constants used throughout the Pycomm3 package for CIP communication."""

from .cip import LogicalSegment, ClassCode

__all__ = [
    "HEADER_SIZE",
    "MSG_ROUTER_PATH",
    "MULTISERVICE_READ_OVERHEAD",
    "MIN_VER_INSTANCE_IDS",
    "MIN_VER_LARGE_CONNECTIONS",
    "MIN_VER_EXTERNAL_ACCESS",
    "MICRO800_PREFIX",
    "EXTENDED_SYMBOL",
    "SUCCESS",
    "INSUFFICIENT_PACKETS",
    "OFFSET_MESSAGE_REQUEST",
    "PAD",
    "PRIORITY",
    "TIMEOUT_TICKS",
    "TIMEOUT_MULTIPLIER",
    "TRANSPORT_CLASS",
    "BASE_TAG_BIT",
    "SEC_TO_US",
    "TEMPLATE_MEMBER_INFO_LEN",
    "STRUCTURE_READ_REPLY",
    "SLC_CMD_CODE",
    "SLC_CMD_REPLY_CODE",
    "SLC_FNC_READ",
    "SLC_FNC_WRITE",
    "SLC_REPLY_START",
    "PCCC_PATH",
]

HEADER_SIZE = 24  #: Size of the CIP packet header in bytes

MSG_ROUTER_PATH = [
    LogicalSegment(ClassCode.message_router, "class_id"),
    LogicalSegment(0x01, "instance_id"),
]  #: Default routing path for message router

MULTISERVICE_READ_OVERHEAD = 10  #: Overhead in bytes for multi-service read packets

MIN_VER_INSTANCE_IDS = 21  #: Minimum firmware version for Symbol Instance Addressing
MIN_VER_LARGE_CONNECTIONS = 20  #: Minimum version for connections >500 bytes
MIN_VER_EXTERNAL_ACCESS = 18  #: Minimum version for ExternalAccess attribute

MICRO800_PREFIX = "2080"  #: Catalog number prefix for Micro800 PLCs

EXTENDED_SYMBOL = b"\x91"  #: Byte indicating an extended symbol

SUCCESS = 0  #: CIP status code for successful operation
INSUFFICIENT_PACKETS = 6  #: CIP status code for insufficient packet data
OFFSET_MESSAGE_REQUEST = 40  #: Byte offset for message request data
PAD = b"\x00"  #: Padding byte
PRIORITY = b"\x0a"  #: Priority byte for CIP messages
TIMEOUT_TICKS = b"\x05"  #: Timeout ticks byte
TIMEOUT_MULTIPLIER = b"\x07"  #: Timeout multiplier byte
TRANSPORT_CLASS = b"\xa3"  #: Transport class byte for CIP
BASE_TAG_BIT = 1 << 26  #: Bit mask for base tag identification

SEC_TO_US = 1_000_000  #: Conversion factor from seconds to microseconds

TEMPLATE_MEMBER_INFO_LEN = 8  #: Length of template member info in bytes (2B bit/array len, 2B datatype, 4B offset)
STRUCTURE_READ_REPLY = b"\xa0\x02"  #: Reply code for structure read

SLC_CMD_CODE = b"\x0F"  #: SLC command code
SLC_CMD_REPLY_CODE = b"\x4F"  #: SLC command reply code
SLC_FNC_READ = b"\xa2"  #: SLC function code for protected typed logical read
SLC_FNC_WRITE = b"\xab"  #: SLC function code for protected typed logical masked write
SLC_REPLY_START = 61  #: Starting offset for SLC reply data
PCCC_PATH = b"\x67\x24\x01"  #: PCCC communication path