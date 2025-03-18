# -*- coding: utf-8 -*-
#
# Original Copyright (c) 2021 Ian Ottoway <ian@ottoway.dev>
# Original Copyright (c) 2014 Agostino Ruscito <ruscito@gmail.com>
# Modifications Copyright (c) 2025 Sergio Gallegos <sergio.gallegos@example.com>
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

"""SLC/MicroLogix PLC driver for Ethernet/IP communication in Pycomm3."""

from __future__ import annotations
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from .cip_driver import CIPDriver, with_forward_open
from .cip import (
    PCCC_CT,
    PCCC_DATA_TYPE,
    PCCC_DATA_SIZE,
    PCCC_ERROR_CODE,
    USINT,
    UINT,
    PCCCDataTypes,
)
from .const import (
    SUCCESS,
    SLC_CMD_CODE,
    SLC_FNC_READ,
    SLC_FNC_WRITE,
    SLC_REPLY_START,
    PCCC_PATH,
)
from .exceptions import ResponseError, RequestError
from .tag import Tag
from .packets import SendUnitDataRequestPacket

__all__ = ["SLCDriver"]

AtomicValueType = Union[int, float, bool]
TagValueType = Union[AtomicValueType, List[Union[AtomicValueType, str]]]
ReadWriteReturnType = Union[Tag, List[Tag]]

IO_RE = re.compile(
    r"(?P<file_type>[IO])(?P<file_number>\d{1,3})?"
    r"(:)(?P<element_number>\d{1,3})"
    r"((\.)(?P<position_number>\d{1,3}))?"
    r"(/(?P<sub_element>\d{1,2}))?"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

CT_RE = re.compile(
    r"(?P<file_type>[CT])(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,3})"
    r"(.)(?P<sub_element>ACC|PRE|EN|DN|TT|CU|CD|DN|OV|UN|UA)",
    flags=re.IGNORECASE,
)

LFBN_RE = re.compile(
    r"(?P<file_type>[LFBN])(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,3})"
    r"(/(?P<sub_element>\d{1,2}))?"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

S_RE = re.compile(
    r"(?P<file_type>S)"
    r"(:)(?P<element_number>\d{1,3})"
    r"(/(?P<sub_element>\d{1,2}))?"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

A_RE = re.compile(
    r"(?P<file_type>A)(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,4})"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

B_RE = re.compile(
    r"(?P<file_type>B)(?P<file_number>\d{1,3})"
    r"(/)(?P<element_number>\d{1,4})"
    r"(?P<_elem_cnt_token>{(?P<element_count>\d+)})?",
    flags=re.IGNORECASE,
)

ST_RE = re.compile(
    r"(?P<file_type>ST)(?P<file_number>\d{1,3})"
    r"(:)(?P<element_number>\d{1,4})"
    r"(?P<_elem_cnt_token>{(?P<element_count>[12])})?",
    flags=re.IGNORECASE,
)


class SLCDriver(CIPDriver):
    """Ethernet/IP driver for SLC and MicroLogix PLCs.

    Supports reading and writing data files using the PCCC protocol over CIP.

    Attributes:
        __log: Logger instance for this class.
        _auto_slot_cip_path: Enables automatic slot path generation.

    Example:
        >>> plc = SLCDriver("192.168.1.100")
        >>> plc.open()
        >>> tag = plc.read("N7:0")
        >>> plc.close()
    """

    __log = logging.getLogger(f"{__module__}.{__qualname__}")
    _auto_slot_cip_path = True

    def __init__(self, path: str, *args: Any, **kwargs: Any) -> None:
        """Initialize the SLCDriver.

        Args:
            path: CIP path to the PLC (e.g., "192.168.1.100").
            *args: Additional positional arguments passed to CIPDriver.
            **kwargs: Additional keyword arguments passed to CIPDriver.
        """
        super().__init__(path, *args, large_packets=False, **kwargs)

    def _msg_start(self) -> bytes:
        """Generate the common message start sequence for PCCC requests.

        Returns:
            bytes: Message start sequence.
        """
        return b"".join(
            (
                b"\x4b",  # Service code
                b"\x02",  # Path size
                b"\x20",  # 8-bit class
                PCCC_PATH,
                b"\x07",  # Requestor ID length
                self._cfg["vid"],
                self._cfg["vsn"],
            )
        )

    @with_forward_open
    def read(self, *addresses: str) -> ReadWriteReturnType:
        """Read data file addresses from the PLC.

        Supports multiple words by appending `{count}` to the address (e.g., "N7:0{10}").

        Args:
            *addresses: One or more data file addresses to read.

        Returns:
            ReadWriteReturnType: Single Tag or list of Tags.

        Example:
            >>> plc.read("N7:0")  # Single value
            >>> plc.read("N7:0{3}")  # Read 3 elements
        """
        results = [self._read_tag(tag) for tag in addresses]
        return results[0] if len(results) == 1 else results

    def _read_tag(self, tag: str) -> Tag:
        """Read a single tag from the PLC.

        Args:
            tag: Data file address (e.g., "N7:0").

        Returns:
            Tag: Result of the read operation.

        Raises:
            RequestError: If tag parsing fails.
        """
        _tag = parse_tag(tag)
        if _tag is None:
            raise RequestError(f"Error parsing tag: {tag}")

        message_request = [
            self._msg_start(),
            SLC_CMD_CODE,
            b"\x00",
            UINT.encode(next(self._sequence)),
            SLC_FNC_READ,
            USINT.encode(PCCC_DATA_SIZE[_tag["file_type"]] * _tag["element_count"]),
            USINT.encode(int(_tag["file_number"])),
            PCCC_DATA_TYPE[_tag["file_type"]],
            USINT.encode(int(_tag["element_number"])),
            USINT.encode(int(_tag.get("pos_number", 0))),
        ]

        request = SendUnitDataRequestPacket(self._sequence)
        request.add(b"".join(message_request))
        response = self.send(request)
        self.__log.debug(f"SLC read_tag({tag})")

        status = request_status(response.raw)
        if status:
            return Tag(_tag["tag"], None, _tag["file_type"], status)

        try:
            return _parse_read_reply(_tag, response.raw[SLC_REPLY_START:])
        except ResponseError as err:
            self.__log.exception(f"Failed to parse read reply for {_tag['tag']}")
            return Tag(_tag["tag"], None, _tag["file_type"], str(err))

    @with_forward_open
    def write(self, *address_values: Tuple[str, TagValueType]) -> ReadWriteReturnType:
        """Write values to data file addresses.

        Supports multiple words with `{count}` (e.g., "N7:0{10}") and a list of values.

        Args:
            *address_values: Tuples of (address, value).

        Returns:
            ReadWriteReturnType: Single Tag or list of Tags.

        Example:
            >>> plc.write(("N7:0", 42))  # Single value
            >>> plc.write(("N7:0{3}", [1, 2, 3]))  # Multiple values
        """
        results = [self._write_tag(tag, value) for tag, value in address_values]
        return results[0] if len(results) == 1 else results

    def _write_tag(self, tag: str, value: TagValueType) -> Tag:
        """Write a value to a single tag.

        Args:
            tag: Data file address (e.g., "N7:0").
            value: Value to write (int, float, bool, or list).

        Returns:
            Tag: Result of the write operation.

        Raises:
            RequestError: If tag parsing or value encoding fails.
        """
        _tag = parse_tag(tag)
        if _tag is None:
            raise RequestError(f"Error parsing tag: {tag}")

        _tag["data_size"] = PCCC_DATA_SIZE[_tag["file_type"]]
        message_request = [
            self._msg_start(),
            SLC_CMD_CODE,
            b"\x00",
            UINT.encode(next(self._sequence)),
            SLC_FNC_WRITE,
            USINT.encode(_tag["data_size"] * _tag["element_count"]),
            USINT.encode(int(_tag["file_number"])),
            PCCC_DATA_TYPE[_tag["file_type"]],
            USINT.encode(int(_tag["element_number"])),
            USINT.encode(int(_tag.get("pos_number", 0))),
            writeable_value(_tag, value),
        ]

        request = SendUnitDataRequestPacket(self._sequence)
        request.add(b"".join(message_request))
        response = self.send(request)

        status = request_status(response.raw)
        return Tag(_tag["tag"], value if status is None else None, _tag["file_type"], status)

    @with_forward_open
    def get_processor_type(self) -> Optional[str]:
        """Retrieve the PLC processor type.

        Returns:
            Optional[str]: Processor type string or None if failed.
        """
        msg_request = (
            self._msg_start(),
            b"\x06",  # Diagnostic status CMD
            b"\x00",
            UINT.encode(next(self._sequence)),
            b"\x03",  # FNC
        )

        request = SendUnitDataRequestPacket(self._sequence)
        request.add(b"".join(msg_request))
        response = self.send(request)

        if not response or request_status(response.raw):
            self.__log.error(f"Failed to get processor type: {request_status(response.raw)}")
            return None

        try:
            return response.raw[SLC_REPLY_START:][5:16].decode("utf-8").strip()
        except Exception as err:
            self.__log.exception(f"Failed parsing processor type: {err}")
            return None

    @with_forward_open
    def get_datalog_queue(self, num_data_logs: int, queue_num: int) -> List[str]:
        """Retrieve datalog queue entries.

        Args:
            num_data_logs: Number of datalog entries to retrieve.
            queue_num: Queue number to read from.

        Returns:
            List[str]: List of datalog entries.

        Raises:
            ResponseError: If queue retrieval fails.
        """
        data = []
        for _ in range(num_data_logs):
            entry = self._get_datalog(queue_num)
            if entry is not None:
                data.append(entry)
            else:
                break

        # Clear queue with an extra read
        self._get_datalog(queue_num)  # Expected to fail silently if empty

        if data:
            return data
        raise ResponseError("No data in queue or retrieval failed")

    def _get_datalog(self, queue_num: int) -> Optional[str]:
        """Retrieve a single datalog entry.

        Args:
            queue_num: Queue number to read from.

        Returns:
            Optional[str]: Datalog entry or None if failed.
        """
        msg_request = [
            b"\x4b",
            b"\x02",
            b"\x20",
            b"\x67",
            b"\x24",
            b"\x01",
            b"\x07",
            b"\x4d\x00",
            b"\xa1\x4e\xc3\x30",
            b"\x0f",
            b"\x00",
            UINT.encode(next(self._sequence)),
            b"\xa2",
            b"\x6d",
            b"\x00",
            b"\xa5",
            USINT.encode(queue_num),
            b"\x00",
        ]

        request = SendUnitDataRequestPacket(self._sequence)
        request.add(b"".join(msg_request))
        response = self.send(request)

        status = request_status(response.raw)
        if status:
            self.__log.error(f"Failed to retrieve datalog: {status}")
            return None

        try:
            return response.raw[SLC_REPLY_START:].decode("utf-8")
        except Exception as err:
            self.__log.exception(f"Failed to decode datalog: {err}")
            return None

    @with_forward_open
    def get_file_directory(self) -> Dict[str, Dict[str, int]]:
        """Retrieve the file directory from the PLC.

        Returns:
            Dict[str, Dict[str, int]]: File directory information.

        Raises:
            ResponseError: If directory retrieval fails.
        """
        plc_type = self.get_processor_type()
        if not plc_type:
            raise ResponseError("Failed to read processor type")

        sys0_info = _get_sys0_info(plc_type)
        sys0_info["size"] = self._get_file_directory_size(sys0_info)
        if sys0_info["size"] is None:
            raise ResponseError("Failed to read file directory size")

        data = self._read_whole_file_directory(sys0_info)
        return _parse_file0(sys0_info, data)

    def _get_file_directory_size(self, sys0_info: Dict[str, Any]) -> Optional[int]:
        """Get the size of the file directory (File 0).

        Args:
            sys0_info: System 0 configuration info.

        Returns:
            Optional[int]: Size in bytes or None if failed.
        """
        msg_request = [
            self._msg_start(),
            SLC_CMD_CODE,
            b"\x00",
            UINT.encode(next(self._sequence)),
            b"\xa1",
            sys0_info["size_len"],
            b"\x00",
            sys0_info["file_type"],
            sys0_info["size_element"],
        ]

        request = SendUnitDataRequestPacket(self._sequence)
        request.add(b"".join(msg_request))
        response = self.send(request)

        status = request_status(response.raw)
        if status:
            self.__log.error(f"Failed to read File 0 size: {status}")
            return None

        try:
            size = UINT.decode(response.raw[SLC_REPLY_START:]) - sys0_info.get("size_const", 0)
            self.__log.debug(f"SYS 0 file size: {size}")
            return size
        except Exception as err:
            self.__log.exception(f"Failed to parse File 0 size: {err}")
            return None

    def _read_whole_file_directory(self, sys0_info: Dict[str, Any]) -> bytes:
        """Read the entire file directory content.

        Args:
            sys0_info: System 0 configuration info.

        Returns:
            bytes: File directory data.

        Raises:
            ResponseError: If reading fails.
        """
        file0_data = b""
        offset = 0
        file0_size = sys0_info["size"]
        file_type = sys0_info["file_type"]

        while len(file0_data) < file0_size:
            bytes_remaining = file0_size - len(file0_data)
            size = min(0x50, bytes_remaining)
            msg_request = [
                self._msg_start(),
                SLC_CMD_CODE,
                b"\x00",
                UINT.encode(next(self._sequence)),
                b"\xa1",
                USINT.encode(size),
                b"\x00",
                file_type,
            ]
            msg_request += [USINT.encode(offset)] if offset < 256 else [b"\xFF", UINT.encode(offset)]

            request = SendUnitDataRequestPacket(self._sequence)
            request.add(b"".join(msg_request))
            response = self.send(request)

            status = request_status(response.raw)
            if status:
                raise ResponseError(f"Error reading File 0 contents: {status}")

            data = response.raw[SLC_REPLY_START:]
            offset += len(data) // 2
            file0_data += data

        return file0_data


def _parse_file0(sys0_info: Dict[str, Any], data: bytes) -> Dict[str, Dict[str, int]]:
    """Parse File 0 data into a directory structure.

    Args:
        sys0_info: System 0 configuration info.
        data: Raw File 0 data.

    Returns:
        Dict[str, Dict[str, int]]: Parsed file directory.
    """
    num_data_files = data[52]
    num_lad_files = data[46]
    print(f"data files: {num_data_files}, logic files: {num_lad_files}")

    file_pos = sys0_info["file_position"]
    row_size = sys0_info["row_size"]
    data_files = {}
    file_num = 0

    while file_pos < len(data):
        file_code = data[file_pos:file_pos + 1]
        file_type = PCCC_DATA_TYPE.get(file_code)
        if file_type:
            file_name = f"{file_type}{file_num}"
            element_size = PCCC_DATA_SIZE.get(file_type, 2)
            file_size = UINT.decode(data[file_pos + 1:])
            data_files[file_name] = {"elements": file_size // element_size, "length": file_size}

        if file_type or file_code == b"\x81":  # Reserved type for skipped file numbers
            file_num += 1
        file_pos += row_size

    return data_files


def _get_sys0_info(plc_type: str) -> Dict[str, Any]:
    """Get System 0 configuration based on PLC type.

    Args:
        plc_type: PLC processor type string.

    Returns:
        Dict[str, Any]: Configuration dictionary.
    """
    prefix = plc_type[:4]
    if prefix == "1761":  # MLX1000, SLC 5/02
        return {
            "file_position": 93,
            "row_size": 8,
            "file_type": b"\x00",
            "size_element": b"\x23",
            "size_len": b"\x04",
        }
    elif prefix in {"1763", "1762", "1764"}:  # MLX 1100, 1200, 1500
        return {
            "file_position": 233,
            "row_size": 10,
            "file_type": b"\x02",
            "size_element": b"\x28",
            "size_len": b"\x08",
            "size_const": 19968,
        }
    elif prefix == "1766":  # MLX 1400
        return {
            "file_position": 233,
            "row_size": 10,
            "file_type": b"\x03",
            "size_element": b"\x2b",
            "size_len": b"\x08",
            "size_const": 19968,
            "file_type_queue": b"\xA5",
        }
    return {  # SLC 5/05 default
        "file_position": 79,
        "row_size": 10,
        "file_type": b"\x01",
        "size_element": b"\x23",
        "size_len": b"\x04",
    }


def _parse_read_reply(tag: Dict[str, Any], data: bytes) -> Tag:
    """Parse a read response from the PLC.

    Args:
        tag: Parsed tag dictionary.
        data: Raw response data.

    Returns:
        Tag: Parsed tag result.

    Raises:
        ResponseError: If parsing fails.
    """
    try:
        bit_read = tag.get("address_field", 0) == 3
        bit_position = int(tag.get("sub_element", 0))
        data_size = PCCC_DATA_SIZE[tag["file_type"]]
        unpack_func = PCCCDataTypes[tag["file_type"]].decode

        if bit_read:
            if tag["file_type"] in {"T", "C"}:
                if bit_position == PCCC_CT["PRE"]:
                    return Tag(tag["tag"], unpack_func(data[2:2 + data_size]), tag["file_type"], None)
                elif bit_position == PCCC_CT["ACC"]:
                    return Tag(tag["tag"], unpack_func(data[4:4 + data_size]), tag["file_type"], None)
            value = unpack_func(data[:data_size])
            return Tag(tag["tag"], get_bit(value, bit_position), tag["file_type"], None)

        values = [unpack_func(data[i:i + data_size]) for i in range(0, len(data), data_size)]
        return Tag(tag["tag"], values if len(values) > 1 else values[0], tag["file_type"], None)
    except Exception as err:
        raise ResponseError(f"Failed parsing read reply for {tag['tag']}") from err


def parse_tag(tag: str) -> Optional[Dict[str, Any]]:
    """Parse a tag string into a dictionary.

    Args:
        tag: Tag string (e.g., "N7:0", "B3/5").

    Returns:
        Optional[Dict[str, Any]]: Parsed tag info or None if invalid.
    """
    for regex in (CT_RE, LFBN_RE, IO_RE, ST_RE, A_RE, S_RE, B_RE):
        match = regex.search(tag)
        if match:
            return _process_tag_match(match, tag)
    return None


def _process_tag_match(match: re.Match, tag: str) -> Dict[str, Any]:
    """Process a regex match into a tag dictionary.

    Args:
        match: Regex match object.
        tag: Original tag string.

    Returns:
        Dict[str, Any]: Parsed tag info.
    """
    groups = match.groupdict()
    _cnt = groups.get("_elem_cnt_token")
    tag_name = tag.replace(_cnt, "") if _cnt else tag
    file_type = groups["file_type"].upper()
    file_number = groups.get("file_number", "2" if file_type == "S" else "0" if file_type == "O" else "1")
    element_number = int(groups["element_number"])
    element_count = int(groups["element_count"]) if groups.get("element_count") else 1

    if file_type in {"C", "T"} and groups.get("sub_element"):
        return {
            "file_type": file_type,
            "file_number": file_number,
            "element_number": element_number,
            "sub_element": PCCC_CT[groups["sub_element"].upper()],
            "address_field": 3,
            "element_count": 1,
            "tag": tag_name,
        }

    if file_type == "B" and "/" in tag:
        bit_position = element_number
        element_number = bit_position // 16
        sub_element = bit_position % 16
        return {
            "file_type": file_type,
            "file_number": file_number,
            "element_number": element_number,
            "sub_element": sub_element,
            "address_field": 3,
            "element_count": element_count,
            "tag": tag_name,
        }

    sub_element = int(groups["sub_element"]) if groups.get("sub_element") else 0
    address_field = 3 if sub_element or groups.get("sub_element") else 2
    return {
        "file_type": file_type,
        "file_number": file_number,
        "element_number": element_number,
        "pos_number": groups.get("position_number", "0"),
        "sub_element": sub_element,
        "address_field": address_field,
        "element_count": element_count,
        "tag": tag_name,
    }


def get_bit(value: int, idx: int) -> bool:
    """Get the value of a specific bit.

    Args:
        value: Integer value.
        idx: Bit index (0-based).

    Returns:
        bool: True if bit is set, False otherwise.
    """
    return bool(value & (1 << idx))


def writeable_value(tag: Dict[str, Any], value: Union[bytes, TagValueType]) -> bytes:
    """Convert a value into a writeable byte sequence.

    Args:
        tag: Parsed tag dictionary.
        value: Value to encode (bytes, int, float, bool, or list).

    Returns:
        bytes: Encoded value with bit mask.

    Raises:
        RequestError: If value encoding fails.
    """
    if isinstance(value, bytes):
        return value

    bit_field = tag.get("address_field", 0) == 3
    bit_position = int(tag.get("sub_element", 0)) if bit_field else 0
    bit_mask = UINT.encode(1 << bit_position) if bit_field else b"\xFF\xFF"
    element_count = tag.get("element_count", 1)

    if element_count > 1:
        if not isinstance(value, (list, tuple)) or len(value) < element_count:
            raise RequestError(f"Expected {element_count} elements, got {len(value) if isinstance(value, (list, tuple)) else 1}")
        value = value[:element_count]
        return bit_mask + b"".join(PCCCDataTypes[tag["file_type"]].encode(val) for val in value)

    pack_func = PCCCDataTypes[tag["file_type"]].encode
    try:
        if bit_field and tag["file_type"] in ["T", "C"] and bit_position in {PCCC_CT["PRE"], PCCC_CT["ACC"]}:
            return b"\xff\xff" + pack_func(value)
        return bit_mask + (bit_mask if value and bit_field else b"\x00\x00") if bit_field else pack_func(value)
    except Exception as err:
        raise RequestError(f"Failed to encode value for {tag['tag']}: {value}") from err


def request_status(data: bytes) -> Optional[str]:
    """Check the status of a response.

    Args:
        data: Raw response data.

    Returns:
        Optional[str]: Error message if status is non-zero, None if successful.
    """
    try:
        status_code = data[58]
        return None if status_code == SUCCESS else PCCC_ERROR_CODE.get(status_code, "Unknown Status")
    except IndexError:
        return "Unknown Status"