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

from __future__ import annotations
import datetime
import enum
import logging
import time
from functools import reduce
from io import BytesIO
from operator import mul
from typing import Any, Optional, Union, Sequence, TypeVar, Literal

from . import util
from .cip import (
    ClassCode,
    Services,
    KEYSWITCH,
    EXTERNAL_ACCESS,
    DataTypes,
    Struct,
    STRING,
    n_bytes,
    ULINT,
    DataSegment,
    USINT,
    UINT,
    LogicalSegment,
    PADDED_EPATH,
    UDINT,
    DINT,
    Array,
    DataType,
    ArrayType,
    PortSegment,
)
from .cip_driver import CIPDriver, with_forward_open, parse_connection_path
from .const import (
    EXTENDED_SYMBOL,
    MICRO800_PREFIX,
    MULTISERVICE_READ_OVERHEAD,
    SUCCESS,
    INSUFFICIENT_PACKETS,
    BASE_TAG_BIT,
    MIN_VER_INSTANCE_IDS,
    SEC_TO_US,
    TEMPLATE_MEMBER_INFO_LEN,
    MIN_VER_EXTERNAL_ACCESS,
)
from .custom_types import (
    StructTemplateAttributes,
    StructTag,
    FixedSizeString,
    ModuleIdentityObject,
)
from .exceptions import ResponseError, RequestError
from .packets import (
    RequestPacket,
    ReadTagFragmentedRequestPacket,
    WriteTagFragmentedRequestPacket,
    ReadTagFragmentedResponsePacket,
    WriteTagFragmentedResponsePacket,
    SendUnitDataRequestPacket,
    ReadTagRequestPacket,
    WriteTagRequestPacket,
    MultiServiceRequestPacket,
    ReadModifyWriteRequestPacket,
)
from .tag import Tag

__all__ = ["LogixDriver"]

# Type aliases for clarity
AtomicValueType = Union[int, float, bool, str]
TagValueType = Union[AtomicValueType, list[AtomicValueType], dict[str, "TagValueType"]]
ReadWriteReturnType = Union[Tag, list[Tag]]
T = TypeVar("T")


class RWMode(enum.Enum):
    """Enumeration for read/write mode in tag parsing."""
    READ = "r"
    WRITE = "w"


class LogixDriver(CIPDriver):
    """An Ethernet/IP client driver for reading and writing tags in ControlLogix and CompactLogix PLCs.

    This driver extends `CIPDriver` to provide high-level functionality for interacting with PLC tags,
    including reading/writing values, retrieving tag definitions, and managing PLC metadata.

    Attributes:
        tags (dict): Read-only dictionary of all tag definitions uploaded from the controller.
        data_types (dict): Read-only dictionary of all data type definitions.
        info (dict): Dictionary of PLC metadata (e.g., vendor, revision, name).
        connected (bool): Indicates if a connection to the PLC is open.
        name (str | None): Name of the PLC program, if available.

    Example:
        >>> driver = LogixDriver("10.20.30.100/1", init_tags=True)
        >>> driver.open()
        >>> tag = driver.read("MyTag")
        >>> print(tag.value)
        >>> driver.close()
    """

    __log = logging.getLogger(f"{__module__}.{__qualname__}")
    _auto_slot_cip_path = True

    def __init__(
        self,
        path: str,
        *,
        init_tags: bool = True,
        init_program_tags: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize the LogixDriver.

        Args:
            path: CIP path to the target PLC (e.g., "10.20.30.100", "10.20.30.100/1", or a full CIP route).
            init_tags: If True, uploads controller-scoped tag definitions on connect.
            init_program_tags: If True, includes program-scoped tags in the upload.
            **kwargs: Additional arguments passed to `CIPDriver`.

        Notes:
            - The `path` can be an IP address, IP/slot, or a full CIP route (e.g., "1.2.3.4/backplane/0").
            - Tag initialization is required for `read` and `write` operations to function correctly.
            - For multiple connections, disable `init_tags` on secondary instances and share tags from the primary.

        Raises:
            ValueError: If the path is malformed or invalid.
        """
        super().__init__(path, **kwargs)
        self._cache: dict[str, dict] | None = None
        self._data_types: dict[str, dict] = {}
        self._tags: dict[str, dict] = {}
        self._micro800: bool = False
        self._cfg["use_instance_ids"] = True
        self._init_args = {"init_tags": init_tags, "init_program_tags": init_program_tags}
        self.__log.debug(f"Initialized with path={path}, init_tags={init_tags}, init_program_tags={init_program_tags}")

    def __str__(self) -> str:
        """String representation of the driver."""
        _rev = self._info.get("revision", {"major": -1, "minor": -1})
        return f"Program Name: {self._info.get('name')}, Revision: {_rev}"

    def __repr__(self) -> str:
        """Detailed string representation of the driver."""
        init_args = ", ".join(f"{k}={v}" for k, v in self._init_args.items())
        return f"{self.__class__.__name__}(path={self._cip_path!r}, {init_args})"

    def open(self) -> bool:
        """Open a connection to the PLC and initialize the driver.

        Returns:
            bool: True if the connection was successfully opened, False otherwise.

        Raises:
            ResponseError: If initialization fails after opening the connection.
        """
        success = super().open()
        if success:
            self._initialize_driver(**self._init_args)
        return success

    def _initialize_driver(self, init_tags: bool, init_program_tags: bool) -> None:
        """Initialize driver state after opening a connection.

        Args:
            init_tags: Whether to upload controller-scoped tags.
            init_program_tags: Whether to include program-scoped tags.

        Raises:
            ResponseError: If identity listing or tag upload fails critically.
        """
        self.__log.info("Initializing driver...")
        target_identity = self._list_identity()
        self.__log.debug(f"Identified target: {target_identity!r}")
        self._micro800 = target_identity.get("product_name", "").startswith(MICRO800_PREFIX)
        self._info = self.get_plc_info()
        self._cfg["use_instance_ids"] = (
            self.revision_major >= MIN_VER_INSTANCE_IDS and not self._micro800
        )
        if not self._micro800:
            self.get_plc_name()
        if self._micro800 and self._cfg["cip_path"] and isinstance(self._cfg["cip_path"][-1], PortSegment):
            self._cfg["cip_path"].pop(-1)  # Remove unnecessary backplane/0 for Micro800
        if init_tags:
            self.get_tag_list(program="*" if init_program_tags else None)
        self.__log.info("Initialization complete.")

    @property
    def revision_major(self) -> int:
        """Major revision number of the PLC firmware.

        Returns:
            int: Major revision, or 0 if unavailable.
        """
        return self.info.get("revision", {}).get("major", 0)

    @property
    def tags(self) -> dict[str, dict]:
        """Dictionary of all tag definitions uploaded from the controller."""
        return self._tags

    @property
    def tags_json(self) -> dict[str, dict]:
        """JSON-serializable dictionary of tag definitions.

        Filters out non-serializable objects like type classes.
        """
        def _copy_datatype(src: dict) -> dict:
            new = {k: v for k, v in src.items() if k not in {"type_class", "_struct_members"}}
            if isinstance(src.get("data_type"), dict):
                new["data_type"] = _copy_datatype(src["data_type"])
            if "internal_tags" in src:
                new["internal_tags"] = {k: _copy_datatype(v) for k, v in src["internal_tags"].items()}
            return new

        return {tag: _copy_datatype(data) for tag, data in self._tags.items()}

    @property
    def data_types(self) -> dict[str, dict]:
        """Dictionary of all data type definitions uploaded from the controller."""
        return self._data_types

    @property
    def connected(self) -> bool:
        """Check if a connection to the PLC is currently open."""
        return self._connection_opened

    @property
    def info(self) -> dict[str, Any]:
        """Metadata about the connected PLC."""
        return self._info

    @property
    def name(self) -> Optional[str]:
        """Name of the PLC program, if available."""
        return self._info.get("name")

    @with_forward_open
    def get_plc_name(self) -> str:
        """Retrieve the name of the program running in the PLC.

        Uses Rockwell Automation KB 23341 for implementation.

        Returns:
            str: The PLC program name.

        Raises:
            ResponseError: If the request fails or the response is invalid.
        """
        response = self.generic_message(
            service=Services.get_attributes_all,
            class_code=ClassCode.program_name,
            instance=1,
            data_type=STRING,
            name="get_plc_name",
        )
        if not response or response.error:
            raise ResponseError(f"Failed to get PLC name: {response.error}")
        self._info["name"] = response.value
        return self._info["name"]

    def get_plc_info(self) -> dict[str, Any]:
        """Read basic information from the controller.

        Stores the result in the `info` property.

        Returns:
            dict: PLC information including vendor, product type, revision, etc.

        Raises:
            ResponseError: If the request fails or response is invalid.
        """
        response = self.generic_message(
            class_code=ClassCode.identity_object,
            instance=b"\x01",
            service=Services.get_attributes_all,
            data_type=ModuleIdentityObject,
            connected=False,
            unconnected_send=not self._micro800,
            name="get_plc_info",
        )
        if not response or response.error:
            raise ResponseError(f"Failed to get PLC info: {response.error}")
        info = response.value
        info["keyswitch"] = KEYSWITCH.get(info["status"][0], {}).get(info["status"][1], "UNKNOWN")
        return info

    def get_plc_time(self, fmt: str = "%A, %B %d, %Y %I:%M:%S%p") -> Tag:
        """Get the current time of the PLC system clock.

        Args:
            fmt: Format string for the string representation of the time.

        Returns:
            Tag: Contains time as a dict with 'datetime', 'microseconds', and 'string' keys.

        Raises:
            ResponseError: If the time retrieval fails.
        """
        tag = self.generic_message(
            service=Services.get_attribute_list,
            class_code=ClassCode.wall_clock_time,
            instance=b"\x01",
            request_data=b"\x01\x00\x0B\x00",
            data_type=Struct(n_bytes(6), ULINT("µs")),
        )
        if tag and not tag.error:
            _time = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=tag.value["µs"])
            value = {
                "datetime": _time,
                "microseconds": tag.value["µs"],
                "string": _time.strftime(fmt),
            }
        else:
            value = None
        return Tag("get_plc_time", value, None, error=tag.error)

    def set_plc_time(self, microseconds: Optional[int] = None) -> Tag:
        """Set the time of the PLC system clock.

        Args:
            microseconds: Timestamp in microseconds; if None, uses client PC clock.

        Returns:
            Tag: Status of the set operation.

        Raises:
            ResponseError: If the set operation fails.
        """
        if microseconds is None:
            microseconds = int(time.time() * SEC_TO_US)
        _struct = Struct(UINT, UINT, ULINT)
        return self.generic_message(
            service=Services.set_attribute_list,
            class_code=ClassCode.wall_clock_time,
            instance=b"\x01",
            request_data=_struct.encode([1, 6, microseconds]),
            name="set_plc_time",
        )

    @with_forward_open
    def get_tag_list(self, program: str | None = None, cache: bool = True) -> list[dict]:
        """Read the tag list and definitions from the controller.

        Args:
            program: Scope of tags to retrieve; None for controller-only, "*" for all, or program name.
            cache: If True, stores the result in the `tags` property.

        Returns:
            list[dict]: List of tag definitions.

        Raises:
            ResponseError: If tag list retrieval fails.
        """
        self._cache = {
            "tag_name:id": {},
            "id:struct": {},
            "handle:id": {},
            "id:udt": {},
        }
        if program in {"*", None}:
            self._info["programs"] = {}
            self._info["tasks"] = {}
            self._info["modules"] = {}
        self.__log.info("Starting tag list upload...")
        if program == "*":
            tags = self._get_tag_list()
            for prog in self._info["programs"]:
                tags += self._get_tag_list(prog)
        else:
            tags = self._get_tag_list(program)
        if cache:
            self._tags = {tag["tag_name"]: tag for tag in tags}
        self._cache = None
        self.__log.info(f"Completed tag list upload. Uploaded {len(self._tags)} tags.")
        return tags

    def _get_tag_list(self, program: str | None = None) -> list[dict]:
        """Retrieve tag list for a specific scope.

        Args:
            program: Program name or None for controller scope.

        Returns:
            list[dict]: List of tag definitions.
        """
        self.__log.info(f'Beginning upload of {program or "controller"} tags...')
        all_tags = self._get_instance_attribute_list_service(program)
        self.__log.info(f'Completed upload of {program or "controller"} tags')
        return self._isolate_user_tags(all_tags, program)

    def _get_instance_attribute_list_service(self, program: str | None = None) -> list[dict]:
        """Get instance attribute list from the symbol object class.

        Args:
            program: Program name or None for controller scope.

        Returns:
            list[dict]: Raw tag data from the PLC.

        Raises:
            ResponseError: If the service request fails.
        """
        last_instance = 0
        tag_list = []
        while last_instance != -1:
            self.__log.debug(f"Getting tags starting with instance {last_instance}")
            _start_instance = last_instance
            _num_tags_start = len(tag_list)
            segments = []
            if program:
                if not program.startswith("Program:"):
                    program = f"Program:{program}"
                segments = [DataSegment(program)]
            segments += [
                LogicalSegment(ClassCode.symbol_object, "class_id"),
                LogicalSegment(last_instance, "instance_id"),
            ]
            new_path = PADDED_EPATH.encode(segments, length=True)
            request = SendUnitDataRequestPacket(self._sequence)
            attributes = [
                b"\x01\x00",  # Symbol name
                b"\x02\x00",  # Symbol type
                b"\x03\x00",  # Symbol address
                b"\x05\x00",  # Symbol object address
                b"\x06\x00",  # Software control
                b"\x08\x00",  # Array dimensions
            ]
            if self.revision_major >= MIN_VER_EXTERNAL_ACCESS:
                attributes.append(b"\x0a\x00")  # External access
            request.add(
                Services.get_instance_attribute_list,
                new_path,
                UINT.encode(len(attributes)),
                *attributes,
            )
            response = self.send(request)
            if not response or response.error:
                raise ResponseError(f"Failed to get attribute list: {response.error}")
            last_instance = self._parse_instance_attribute_list(response, tag_list)
            self.__log.debug(f"Uploaded {len(tag_list) - _num_tags_start} tags, last instance: {last_instance}")
        return tag_list

    def _parse_instance_attribute_list(self, response: Any, tag_list: list[dict]) -> int:
        """Parse the instance attribute list response.

        Args:
            response: Response packet from the PLC.
            tag_list: List to append parsed tags to.

        Returns:
            int: Next instance ID or -1 if complete.

        Raises:
            ResponseError: If parsing fails.
        """
        stream = BytesIO(response.data)
        tags_returned_length = stream.getbuffer().nbytes
        count = instance = 0
        try:
            while stream.tell() < tags_returned_length:
                instance = UDINT.decode(stream)
                tag_name = STRING.decode(stream)
                symbol_type = UINT.decode(stream)
                count += 1
                symbol_address = UDINT.decode(stream)
                symbol_object_address = UDINT.decode(stream)
                software_control = UDINT.decode(stream)
                dim1 = UDINT.decode(stream)
                dim2 = UDINT.decode(stream)
                dim3 = UDINT.decode(stream)
                access = USINT.decode(stream) if self.revision_major >= MIN_VER_EXTERNAL_ACCESS else None
                tag_list.append({
                    "instance_id": instance,
                    "tag_name": tag_name,
                    "symbol_type": symbol_type,
                    "symbol_address": symbol_address,
                    "symbol_object_address": symbol_object_address,
                    "software_control": software_control,
                    "external_access": EXTERNAL_ACCESS.get(access, "Unknown"),
                    "dimensions": [dim1, dim2, dim3],
                })
        except ValueError as err:
            raise ResponseError(f"Failed to parse instance attribute list: {err}")
        if response.service_status == SUCCESS:
            return -1
        elif response.service_status == INSUFFICIENT_PACKETS:
            return instance + 1
        self.__log.warning("Unknown status during _parse_instance_attribute_list")
        return -1

    def _isolate_user_tags(self, all_tags: list[dict], program: str | None = None) -> list[dict]:
        """Filter out system tags and isolate user-defined tags.

        Args:
            all_tags: Raw tag data from the PLC.
            program: Program scope, if applicable.

        Returns:
            list[dict]: List of user tag definitions.

        Raises:
            ResponseError: If processing fails.
        """
        user_tags = []
        self.__log.debug(f'Isolating user tags for {program or "controller"} ...')
        for tag in all_tags:
            io_tag = False
            name = tag["tag_name"]
            if name.startswith("Program:"):
                prog_name = name.replace("Program:", "")
                self._info["programs"][prog_name] = {"instance_id": tag["instance_id"], "routines": []}
                continue
            if name.startswith("Routine:"):
                rtn_name = name.replace("Routine:", "")
                _program = self._info["programs"].get(program)
                if _program:
                    _program["routines"].append(rtn_name)
                else:
                    self.__log.error(f"Program {program} not defined in tag list")
                continue
            if name.startswith("Task:"):
                self._info["tasks"][name.replace("Task:", "")] = {"instance_id": tag["instance_id"]}
                continue
            if "Map:" in name or "Cxn:" in name:
                continue
            if any(x in name for x in (":I", ":O", ":C", ":S")):
                io_tag = True
                mod = name.split(":")
                mod_name = mod[0]
                if mod_name not in self._info["modules"]:
                    self._info["modules"][mod_name] = {"slots": {}}
                if len(mod) == 3 and mod[1].isdigit():
                    mod_slot = int(mod[1])
                    if mod_slot not in self._info["modules"][mod_name]:
                        self._info["modules"][mod_name]["slots"][mod_slot] = {"types": []}
                    self._info["modules"][mod_name]["slots"][mod_slot]["types"].append(mod[2])
                elif len(mod) == 2:
                    if "types" not in self._info["modules"][mod_name]:
                        self._info["modules"][mod_name]["types"] = []
                    self._info["modules"][mod_name]["types"].append(mod[1])
                else:
                    if "__UNKNOWN__" not in self._info["modules"][mod_name]:
                        self._info["modules"][mod_name]["__UNKNOWN__"] = []
                    self._info["modules"][mod_name]["__UNKNOWN__"].append(":".join(mod[1:]))
            if (not io_tag and ":" in name) or name.startswith("__"):
                continue
            if tag["symbol_type"] & 0b0001_0000_0000_0000:
                continue
            if program:
                name = f"Program:{program}.{name}"
            self._cache["tag_name:id"][name] = tag["instance_id"]
            user_tags.append(self._create_tag(name, tag))
        self.__log.debug(f'Finished isolating tags for {program or "controller"}')
        return user_tags

    def _create_tag(self, name: str, raw_tag: dict) -> dict:
        """Create a structured tag definition from raw data.

        Args:
            name: Tag name.
            raw_tag: Raw tag data from the PLC.

        Returns:
            dict: Processed tag definition.
        """
        copy_keys = [
            "instance_id",
            "symbol_address",
            "symbol_object_address",
            "software_control",
            "external_access",
            "dimensions",
        ]
        new_tag = {
            "tag_name": name,
            "dim": (raw_tag["symbol_type"] & 0b0110000000000000) >> 13,
            "alias": False if raw_tag["software_control"] & BASE_TAG_BIT else True,
            **{k: raw_tag[k] for k in copy_keys},
        }
        if raw_tag["symbol_type"] & 0b_1000_0000_0000_0000:
            template_instance_id = raw_tag["symbol_type"] & 0b_0000_1111_1111_1111
            tag_type = "struct"
            new_tag["template_instance_id"] = template_instance_id
            new_tag["data_type"] = self._get_data_type(template_instance_id, raw_tag["symbol_type"])
            new_tag["data_type_name"] = new_tag["data_type"]["name"]
        else:
            tag_type = "atomic"
            datatype = raw_tag["symbol_type"] & 0b_0000_0000_1111_1111
            new_tag["data_type"] = DataTypes.get(datatype)
            new_tag["data_type_name"] = new_tag["data_type"]
            new_tag["type_class"] = DataTypes.get(new_tag["data_type"])
            if datatype == DataTypes.bool.code:
                new_tag["bit_position"] = (raw_tag["symbol_type"] & 0b_0000_0111_0000_0000) >> 8
        _type_class = (
            new_tag["data_type"]["type_class"] if tag_type == "struct" else DataTypes.get(new_tag["data_type"])
        )
        if new_tag["dim"]:
            total_elements = reduce(mul, new_tag["dimensions"][: new_tag["dim"]], 1)
            type_class = Array(length_=total_elements, element_type_=_type_class)
        else:
            type_class = _type_class
        new_tag["tag_type"] = tag_type
        new_tag["type_class"] = type_class
        return new_tag

    def _get_structure_makeup(self, instance_id: int) -> dict:
        """Get the structure makeup for a specific structure.

        Args:
            instance_id: Instance ID of the structure.

        Returns:
            dict: Structure makeup details.

        Raises:
            ResponseError: If the request fails.
        """
        if instance_id not in self._cache["id:struct"]:
            attrs = (
                b"\x04\x00",  # Number of attributes
                b"\x04\x00",  # Template Object Definition Size UDINT
                b"\x05\x00",  # Template Structure Size UDINT
                b"\x02\x00",  # Template Member Count UINT
                b"\x01\x00",  # Structure Handle UINT
            )
            response = self.generic_message(
                service=Services.get_attribute_list,
                class_code=ClassCode.template_object,
                instance=instance_id,
                connected=True,
                request_data=b"".join(attrs),
                data_type=StructTemplateAttributes,
                name=f"_get_structure_makeup(instance_id={instance_id!r})",
            )
            if not response or response.error:
                raise ResponseError(f"Failed to get structure makeup: {response.error}")
            _struct = _parse_structure_makeup_attributes(response)
            self._cache["id:struct"][instance_id] = _struct
            self._cache["handle:id"][_struct["structure_handle"]] = instance_id
        return self._cache["id:struct"][instance_id]

    def _read_template(self, instance_id: int, object_definition_size: int) -> bytes:
        """Read the template data for a structure.

        Args:
            instance_id: Instance ID of the template.
            object_definition_size: Size of the object definition.

        Returns:
            bytes: Raw template data.

        Raises:
            ResponseError: If reading fails.
        """
        offset = 0
        template_raw = b""
        while True:
            response = self.generic_message(
                service=Services.read_tag,
                class_code=ClassCode.template_object,
                instance=instance_id,
                request_data=b"".join(
                    (DINT.encode(offset), UINT.encode(((object_definition_size * 4) - 21) - offset))
                ),
                name=f"_read_template(instance_id={instance_id}, object_definition_size={object_definition_size})",
                return_response_packet=True,
            )
            response_pkt = response.value
            if response_pkt.service_status not in (SUCCESS, INSUFFICIENT_PACKETS):
                raise ResponseError(f"Error reading template: {response.error}")
            template_raw += response_pkt.data
            if response_pkt.service_status == SUCCESS:
                break
            offset += len(response_pkt.data)
        return template_raw

    def _parse_template_data(self, data: bytes, template: dict, symbol_type: int) -> dict:
        """Parse template data into a data type definition.

        Args:
            data: Raw template data.
            template: Template metadata.
            symbol_type: Symbol type from the tag.

        Returns:
            dict: Data type definition.

        Raises:
            ResponseError: If parsing fails.
        """
        info_len = template["member_count"] * TEMPLATE_MEMBER_INFO_LEN
        info_data = data[:info_len]
        self.__log.debug(f"Parsing template {template!r} from {data!r}")
        chunks = (info_data[i : i + TEMPLATE_MEMBER_INFO_LEN] for i in range(0, info_len, TEMPLATE_MEMBER_INFO_LEN))
        member_data = [self._parse_template_data_member_info(chunk) for chunk in chunks]
        member_names = []
        template_name = None
        try:
            for name in (x.decode(errors="replace") for x in data[info_len:].split(b"\x00")):
                if template_name is None and ";" in name:
                    template_name, _ = name.split(";", maxsplit=1)
                else:
                    member_names.append(name)
        except ValueError as err:
            raise ResponseError("Unable to decode template or member names") from err
        _type = symbol_type & 0b_0000_1111_1111_1111
        predefine = _type < 0x100 or _type > 0xEFF
        if predefine and template_name is None:
            template_name = member_names.pop(0)
        if template_name == "ASCIISTRING82":
            template_name = "STRING"
        data_type = {
            "name": template_name,
            "internal_tags": {},
            "attributes": [],
            "template": template,
        }
        _struct_members = []
        _bit_members = {}
        _private_members = set()
        _unk_member_count = 0
        for member, info in zip(member_names, member_data):
            if not member:
                member = f'__unknown{_unk_member_count}'
                _unk_member_count += 1
            if (
                member.startswith("ZZZZZZZZZZ") or
                member.startswith("__") or
                (predefine and member in {"CTL", "Control"})
            ):
                _private_members.add(member)
            else:
                data_type["attributes"].append(member)
            data_type["internal_tags"][member] = info
            if info["data_type_name"] == "BOOL" and "bit" in info:
                _bit_members[member] = (info["offset"], info["bit"])
            else:
                _struct_members.append((info["type_class"](member), info["offset"]))
        if (
            data_type["attributes"] == ["LEN", "DATA"] and
            data_type["internal_tags"]["DATA"]["data_type_name"] == "SINT" and
            data_type["internal_tags"]["DATA"].get("array")
        ):
            data_type["string"] = data_type["internal_tags"]["DATA"]["array"]
            data_type["type_class"] = FixedSizeString(template["structure_size"] - 4)
        else:
            data_type["_struct_members"] = (_struct_members, _bit_members)
            data_type["type_class"] = StructTag(
                *_struct_members,
                bit_members=_bit_members,
                struct_size=template["structure_size"],
                private_members=_private_members,
            )
        self.__log.debug(f"Completed parsing template as data type {data_type!r}")
        return data_type

    def _parse_template_data_member_info(self, info: bytes) -> dict:
        """Parse member info from template data.

        Args:
            info: Raw member info bytes.

        Returns:
            dict: Member definition.
        """
        stream = BytesIO(info)
        type_info = UINT.decode(stream)
        typ = UINT.decode(stream)
        member = {"offset": UDINT.decode(stream)}
        tag_type = "atomic"
        data_type = DataTypes.get(typ)
        if data_type:
            type_class = DataTypes.get_type(typ)
        if data_type is None:
            instance_id = typ & 0b0000_1111_1111_1111
            type_class = DataTypes.get_type(instance_id)
            if type_class:
                data_type = str(type_class)
        if data_type is None:
            tag_type = "struct"
            data_type = self._get_data_type(instance_id, typ)
            type_class = data_type["type_class"]
        member["tag_type"] = tag_type
        member["data_type"] = data_type
        member["data_type_name"] = data_type["name"] if tag_type == "struct" else data_type
        if data_type == "BOOL":
            member["bit"] = type_info
        elif data_type is not None:
            member["array"] = type_info
            if type_info:
                type_class = Array(length_=type_info, element_type_=type_class)
        member["type_class"] = type_class
        return member

    def _get_data_type(self, instance_id: int, symbol_type: int) -> dict:
        """Get data type definition for a structure.

        Args:
            instance_id: Instance ID of the data type.
            symbol_type: Symbol type from the tag.

        Returns:
            dict: Data type definition.

        Raises:
            ResponseError: If retrieval fails.
        """
        if instance_id not in self._cache["id:udt"]:
            self.__log.debug(f"Getting data type for id {instance_id}")
            template = self._get_structure_makeup(instance_id)
            if not template.get("error"):
                _data = self._read_template(instance_id, template["object_definition_size"])
                data_type = self._parse_template_data(_data, template, symbol_type)
                self._cache["id:udt"][instance_id] = data_type
                self._data_types[data_type["name"]] = data_type
                self.__log.debug(f'Got data type {data_type["name"]} for id {instance_id}')
            else:
                raise ResponseError(f"Failed to get data type information for {instance_id}: {template['error']}")
        return self._cache["id:udt"][instance_id]

    @with_forward_open
    def read(self, *tags: str) -> ReadWriteReturnType:
        """Read the value of one or more tags from the PLC.

        Automatically splits requests based on size, using multi-service or fragmented reads as needed.
        Supports arrays (e.g., "array{10}") and structure reading (returns a dict).

        Args:
            *tags: One or more tag names to read (e.g., "MyTag", "MyArray{5}", "Struct.Tag").

        Returns:
            Tag | list[Tag]: A single Tag object if one tag is provided, otherwise a list of Tags.

        Raises:
            ValueError: If no tags are provided.
            RequestError: If tag parsing fails or tags are invalid.
            ResponseError: If communication with the PLC fails.
        """
        if not tags:
            raise ValueError("At least one tag must be provided")
        parsed_requests = self._parse_requested_tags(tags, RWMode.READ)
        requests = self._build_requests(parsed_requests, RWMode.READ)
        results = self._send_requests(requests)
        return self._process_results(tags, parsed_requests, results, RWMode.READ)

    @with_forward_open
    def write(self, *tags_values: Union[str, TagValueType, tuple[str, TagValueType]]) -> ReadWriteReturnType:
        """Write values to one or more tags in the PLC.

        Supports single (tag, value) pairs or sequences of pairs. Handles multi-service and fragmented writes.

        Args:
            *tags_values: Either a single (tag, value) tuple or multiple tuples (e.g., ("Tag1", 42), ("Tag2", True)).

        Returns:
            Tag | list[Tag]: A single Tag object if one tag is provided, otherwise a list of Tags.

        Raises:
            ValueError: If input format is invalid.
            RequestError: If tag parsing or value encoding fails.
            ResponseError: If communication with the PLC fails.
        """
        if not tags_values:
            raise ValueError("At least one tag-value pair must be provided")
        if len(tags_values) == 2 and isinstance(tags_values[0], str):
            tags_values = (tags_values,)
        if not all(isinstance(tv, tuple) and len(tv) == 2 for tv in tags_values):
            raise ValueError("Tags_values must be (tag, value) tuples")
        tags = [tv[0] for tv in tags_values]
        parsed_requests = self._parse_requested_tags(tags, RWMode.WRITE)
        for i, (_, value) in enumerate(tags_values):
            parsed_requests[i]["value"] = value
        requests = self._build_requests(parsed_requests, RWMode.WRITE)
        results = self._send_requests(requests)
        for r in requests:
            if isinstance(r, ReadModifyWriteRequestPacket):
                result = results.pop(r.request_id)
                for req_id in r._request_ids:
                    results[req_id] = result
        return self._process_results(tags, parsed_requests, results, RWMode.WRITE)

    def _parse_requested_tags(self, tags: Sequence[str], mode: RWMode) -> dict[int, dict]:
        """Parse tag requests into a structured format.

        Args:
            tags: Sequence of tag names to parse.
            mode: Read or write mode affecting parsing logic.

        Returns:
            dict[int, dict]: Mapping of request IDs to parsed tag data.

        Raises:
            RequestError: If any tag cannot be parsed.
        """
        requests = {}
        for i, tag in enumerate(tags):
            parsed = {"request_id": i, "request_tag": tag}
            try:
                parsed_request = self._parse_tag_request(tag, mode)
                if parsed_request:
                    parsed.update(parsed_request)
            except RequestError as err:
                self.__log.error(f"Failed to parse tag request '{tag}': {err}")
                parsed["error"] = str(err)
            requests[i] = parsed
        return requests

    def _parse_tag_request(self, tag: str, mode: RWMode) -> dict:
        """Parse a single tag request.

        Args:
            tag: Tag name to parse.
            mode: Read or write mode.

        Returns:
            dict: Parsed tag data.

        Raises:
            RequestError: If parsing fails.
        """
        try:
            if tag.endswith("}") and "{" in tag:
                tag, _tmp = tag.split("{")
                elements = int(_tmp[:-1])
                implicit_element = False
            else:
                elements = 1
                implicit_element = True
            request_tag = tag
            bit = None
            bool_elements = None
            base, *attrs = tag.split(".")
            if base.startswith("Program:"):
                base = f"{base}.{attrs.pop(0)}"
            if len(attrs) and attrs[-1].isdigit():
                bit = int(attrs.pop(-1))
                tag = base if not len(attrs) else f"{base}.{'.'.join(attrs)}"
            tag_info = self._get_tag_info(base, attrs)
            if tag_info["data_type"] == "DWORD":
                _tag, idx = util.get_array_index(tag)
                if idx is not None:
                    tag = f"{_tag}[0]" if mode == RWMode.READ else f"{_tag}[{idx // 32}]"
                bit = idx
                bool_elements = None if implicit_element or elements == 1 else elements
                total_size = (bit or 0) + elements
                elements = (total_size // 32) + (1 if total_size % 32 else 0)
            return {
                "user_tag": request_tag,
                "plc_tag": tag,
                "bit": bit,
                "elements": elements,
                "tag_info": tag_info,
                "bool_elements": bool_elements,
            }
        except ValueError as err:
            raise RequestError(f"Failed to parse tag request '{tag}': Invalid format - {err}")
        except RequestError as err:
            raise
        except Exception as err:
            raise RequestError(f"Failed to parse tag request '{tag}'") from err

    def _build_requests(self, parsed_tags: dict[int, dict], mode: RWMode) -> list[RequestPacket]:
        """Build request packets based on parsed tag data.

        Args:
            parsed_tags: Parsed tag data from `_parse_requested_tags`.
            mode: Read or write mode.

        Returns:
            list[RequestPacket]: List of constructed request packets.
        """
        if len(parsed_tags) > 1 and not self._micro800:
            return self._build_multi_requests(parsed_tags, mode)
        return [req for req in (self._build_single_request(pt, mode) for pt in parsed_tags.values()) if req]

    def _build_multi_requests(self, parsed_tags: dict[int, dict], mode: RWMode) -> list[RequestPacket]:
        """Build multi-service and fragmented request packets.

        Args:
            parsed_tags: Parsed tag data.
            mode: Read or write mode.

        Returns:
            list[RequestPacket]: List of multi-service and fragmented requests.
        """
        multi_requests = []
        fragmented_requests = []
        requests = []
        bit_writes = {}
        for request_id, tag_data in parsed_tags.items():
            if tag_data.get("error"):
                self.__log.error(f"Skipping request for {tag_data['request_tag']}: {tag_data['error']}")
                continue
            if mode == RWMode.WRITE and tag_data.get("bit") is not None and tag_data.get("bool_elements") is None:
                if tag_data["plc_tag"] not in bit_writes:
                    request = ReadModifyWriteRequestPacket(
                        self._sequence,
                        tag_data["plc_tag"],
                        tag_data["tag_info"],
                        -1 * (1 + len(bit_writes)),
                        self._cfg["use_instance_ids"],
                    )
                    bit_writes[tag_data["plc_tag"]] = request
                else:
                    request = bit_writes[tag_data["plc_tag"]]
                request.set_bit(tag_data["bit"], tag_data["value"], tag_data["request_id"])
                continue
            if mode == RWMode.WRITE:
                try:
                    tag_data["write_value"] = encode_value(tag_data)
                except RequestError as err:
                    tag_data["error"] = str(err)
                    continue
                request = WriteTagRequestPacket(
                    self._sequence,
                    tag_data["plc_tag"],
                    tag_data["elements"],
                    tag_data["tag_info"],
                    request_id,
                    self._cfg["use_instance_ids"],
                    tag_data["write_value"],
                )
            else:
                request = ReadTagRequestPacket(
                    self._sequence,
                    tag_data["plc_tag"],
                    tag_data["elements"],
                    tag_data["tag_info"],
                    request_id,
                    self._cfg["use_instance_ids"],
                )
            request.build_message()
            return_size = _tag_return_size(tag_data) + len(request.message) + 2
            if return_size > self.connection_size:
                if mode == RWMode.READ:
                    request = ReadTagFragmentedRequestPacket.from_request(self._sequence, request)
                else:
                    request = WriteTagFragmentedRequestPacket.from_request(self._sequence, request)
                fragmented_requests.append(request)
            else:
                requests.append((request, return_size))
        grouped_requests = [[]]
        current_group = grouped_requests[0]
        current_response_size = MULTISERVICE_READ_OVERHEAD
        for req, resp_size in requests:
            if current_response_size + resp_size > self.connection_size:
                current_group = []
                grouped_requests.append(current_group)
                current_response_size = MULTISERVICE_READ_OVERHEAD
            current_group.append(req)
            current_response_size += resp_size
        if grouped_requests[0]:
            multi_requests = [MultiServiceRequestPacket(self._sequence, group) for group in grouped_requests]
        return multi_requests + fragmented_requests + list(bit_writes.values())

    def _build_single_request(self, parsed_tag: dict, mode: RWMode) -> RequestPacket | None:
        """Build a single request packet.

        Args:
            parsed_tag: Parsed tag data.
            mode: Read or write mode.

        Returns:
            RequestPacket | None: The request packet or None if errored.
        """
        if parsed_tag.get("error"):
            self.__log.error(f"Skipping request: {parsed_tag['error']}")
            return None
        try:
            if mode == RWMode.WRITE and parsed_tag.get("bit") is not None and parsed_tag.get("bool_elements") is None:
                request = ReadModifyWriteRequestPacket(
                    self._sequence,
                    parsed_tag["plc_tag"],
                    parsed_tag["tag_info"],
                    parsed_tag["request_id"],
                    self._cfg["use_instance_ids"],
                )
                request.set_bit(parsed_tag["bit"], parsed_tag["value"], parsed_tag["request_id"])
            else:
                if mode == RWMode.WRITE:
                    parsed_tag["write_value"] = encode_value(parsed_tag)
                    request = WriteTagRequestPacket(
                        self._sequence,
                        parsed_tag["plc_tag"],
                        parsed_tag["elements"],
                        parsed_tag["tag_info"],
                        parsed_tag["request_id"],
                        self._cfg["use_instance_ids"],
                        parsed_tag["write_value"],
                    )
                else:
                    request = ReadTagRequestPacket(
                        self._sequence,
                        parsed_tag["plc_tag"],
                        parsed_tag["elements"],
                        parsed_tag["tag_info"],
                        parsed_tag["request_id"],
                        self._cfg["use_instance_ids"],
                    )
                request.build_message()
                return_size = _tag_return_size(parsed_tag) + len(request.message)
                if return_size > self.connection_size:
                    if mode == RWMode.READ:
                        request = ReadTagFragmentedRequestPacket.from_request(self._sequence, request)
                    else:
                        request = WriteTagFragmentedRequestPacket.from_request(self._sequence, request)
            return request
        except RequestError as err:
            self.__log.error(f"Failed to build request for {parsed_tag['plc_tag']}: {err}")
            parsed_tag["error"] = str(err)
            return None

    def _process_results(self, tags: Sequence[str], parsed_requests: dict[int, dict], results: dict[int, Tag], mode: RWMode) -> ReadWriteReturnType:
        """Process request results into Tag objects.

        Args:
            tags: Original tag names or tag-value pairs.
            parsed_requests: Parsed tag data.
            results: Raw results from sending requests.
            mode: Read or write mode.

        Returns:
            Tag | list[Tag]: Processed results.
        """
        processed = []
        values = [tag[1] if mode == RWMode.WRITE else None for tag in (tags if mode == RWMode.WRITE else [(t, None) for t in tags])]
        for i, (tag, value) in enumerate(zip(tags, values)):
            request_data = parsed_requests[i]
            if request_data.get("error"):
                processed.append(Tag(tag, None, None, request_data["error"]))
                continue
            result = results.get(i, Tag(tag, None, None, "No response received"))
            try:
                if mode == RWMode.READ:
                    bool_elements = request_data["bool_elements"]
                    if result and not result.error:
                        bit = request_data.get("bit")
                        if request_data["tag_info"]["data_type_name"] != "DWORD":
                            if bit is not None:
                                result = Tag(request_data["user_tag"], bool(result.value & 1 << bit), "BOOL", result.error)
                        else:
                            bit = bit or 0
                            if bool_elements is not None:
                                bools = result.value[bit:bit + bool_elements]
                                data_type = f"BOOL[{bool_elements}]"
                                result = Tag(request_data["user_tag"], bools, data_type, result.error)
                            else:
                                val = result.value[bit]
                                result = Tag(request_data["user_tag"], val, "BOOL", result.error)
                    else:
                        result = Tag(request_data["user_tag"], None, None, result.error)
                else:
                    bit = request_data.get("bit")
                    data_type = request_data["tag_info"]["data_type_name"]
                    bool_elements = request_data["bool_elements"]
                    if bit is not None and bool_elements is None:
                        data_type = "BOOL"
                    elif bool_elements:
                        data_type = f"BOOL[{bool_elements}]"
                    elif request_data["elements"] > 1:
                        data_type = f"{data_type}[{request_data['elements']}]"
                    result = Tag(request_data["user_tag"], value, data_type, result.error)
                processed.append(result)
            except Exception as err:
                self.__log.exception(f"Failed to process result for {tag}")
                processed.append(Tag(tag, None, None, f"Invalid tag request: {err!r}"))
        return processed[0] if len(tags) == 1 else processed

    def get_tag_info(self, tag_name: str) -> Optional[dict]:
        """Get tag information from the uploaded tag list.

        Args:
            tag_name: Name of the tag to retrieve info for.

        Returns:
            dict | None: Tag definition or None if not found.

        Raises:
            RequestError: If tag lookup fails.
        """
        base, *attrs = tag_name.split(".")
        if base.startswith("Program:"):
            base = f"{base}.{attrs.pop(0)}"
        return self._get_tag_info(base, attrs)

    def _get_tag_info(self, base: str, attrs: list[str]) -> Optional[dict]:
        """Recursively get tag info for a base tag and its attributes.

        Args:
            base: Base tag name.
            attrs: List of attribute names.

        Returns:
            dict | None: Tag info or None if not found.

        Raises:
            RequestError: If tag or attribute is invalid.
        """
        def _recurse_attrs(attrs: list[str], data: dict) -> dict | None:
            cur, *remain = attrs
            curr_tag = util.strip_array(cur)
            if not remain:
                return data[curr_tag]
            if curr_tag in data:
                return _recurse_attrs(remain, data[curr_tag]["data_type"]["internal_tags"])
            return None
        try:
            data = self._tags[util.strip_array(base)]
            return data if not attrs else _recurse_attrs(attrs, data["data_type"]["internal_tags"])
        except KeyError as err:
            raise RequestError(f"Tag doesn't exist: {err.args[0]}")
        except Exception as err:
            msg = f"Failed to get tag data for: {base}, {attrs}"
            self.__log.exception(msg)
            raise RequestError(msg) from err

    def _send_requests(self, requests: list[RequestPacket]) -> dict[int, Tag]:
        """Send a list of requests and collect results.

        Args:
            requests: List of request packets.

        Returns:
            dict[int, Tag]: Mapping of request IDs to results.
        """
        results = {}
        for request in requests:
            try:
                response = self.send(request)
            except (RequestError, ResponseError) as err:
                self.__log.exception(f"Error sending request: {err}")
                if request.type_ != "multi":
                    results[request.request_id] = Tag(request.tag, None, None, str(err))
                else:
                    for tag in request.requests:  # Assuming 'requests' attribute for MultiServiceRequestPacket
                        results[tag.request_id] = Tag(tag.tag, None, None, str(err))
            else:
                if request.type_ != "multi":
                    if response and not response.error:
                        results[request.request_id] = Tag(
                            request.tag,
                            response.value if request.type_ == "read" else request.value,
                            response.data_type if request.type_ == "read" else request.data_type,
                            response.error,
                        )
                    else:
                        results[request.request_id] = Tag(request.tag, None, None, response.error)
                else:
                    for resp in response.responses:
                        req = resp.request
                        if resp and not resp.error:
                            results[req.request_id] = Tag(resp.tag, resp.value, resp.data_type, None)
                        else:
                            results[req.request_id] = Tag(req.tag, None, None, req.error or resp.error)
        return results

    def send(self, request: RequestPacket) -> Any:
        """Send a request packet to the PLC and return the response.

        Args:
            request: The request packet to send.

        Returns:
            Any: Response object, varies by request type.

        Raises:
            ResponseError: If the send operation fails.
        """
        if isinstance(request, ReadTagFragmentedRequestPacket):
            return self._send_read_fragmented(request)
        elif isinstance(request, WriteTagFragmentedRequestPacket):
            return self._send_write_fragmented(request)
        return super().send(request)

    def _send_read_fragmented(self, request: ReadTagFragmentedRequestPacket) -> ReadTagFragmentedResponsePacket:
        """Send a fragmented read request and reassemble the response.

        Args:
            request: Fragmented read request packet.

        Returns:
            ReadTagFragmentedResponsePacket: Reassembled response.
        """
        if request.error:
            failed = ReadTagFragmentedResponsePacket(request, None)
            failed._error = request.error
            return failed
        offset = 0
        responses = []
        while offset is not None:
            response: ReadTagFragmentedResponsePacket = super().send(request)
            responses.append(response)
            if response.service_status == INSUFFICIENT_PACKETS:
                offset += len(response.value_bytes)
                request = ReadTagFragmentedRequestPacket.from_request(self._sequence, request, offset)
            else:
                if response.error:
                    self.__log.error(f"Fragment failed with error: {response.error}")
                offset = None
        if all(responses) and not any(r.error for r in responses):
            final_response = responses[-1]
            final_response.value_bytes = b"".join(resp.value_bytes for resp in responses)
            final_response.parse_value()
            self.__log.debug(f"Reassembled Response: {final_response!r}")
            return final_response
        failed = ReadTagFragmentedResponsePacket(request, None)
        failed._error = request.error or "One or more fragment responses failed"
        self.__log.debug(f"Reassembled Response: {failed!r}")
        return failed

    def _send_write_fragmented(self, request: WriteTagFragmentedRequestPacket) -> WriteTagFragmentedResponsePacket:
        """Send a fragmented write request.

        Args:
            request: Fragmented write request packet.

        Returns:
            WriteTagFragmentedResponsePacket: Final response.
        """
        if request.error:
            failed = WriteTagFragmentedResponsePacket(request, None)
            failed._error = request.error
            return failed
        responses = []
        request.build_message()
        segment_size = self.connection_size - (len(request.message) - len(request.value))
        segments = (request.value[i:i + segment_size] for i in range(0, len(request.value), segment_size))
        offset = 0
        for segment in segments:
            _request = WriteTagFragmentedRequestPacket.from_request(self._sequence, request, offset, segment)
            _response = super().send(_request)
            offset += len(segment)
            responses.append(_response)
        if all(responses) and not any(r.error for r in responses):
            final_response = responses[-1]
            self.__log.debug(f"Final Response: {final_response!r}")
            return final_response
        failed = WriteTagFragmentedResponsePacket(request, None)
        failed._error = request.error or "One or more fragment responses failed"
        self.__log.debug(f"Reassembled Response: {failed!r}")
        return failed


def _parse_structure_makeup_attributes(response: Any) -> dict:
    """Extract structure makeup from a response.

    Args:
        response: Response packet.

    Returns:
        dict: Structure makeup details or error info.

    Raises:
        ResponseError: If parsing fails.
    """
    structure = {}
    if not response or response.error:
        structure["error"] = response.error
        return structure
    try:
        _struct = response.value
        structure["object_definition_size"] = _struct["object_definition_size"]["size"]
        structure["structure_size"] = _struct["structure_size"]["size"]
        structure["member_count"] = _struct["member_count"]["count"]
        structure["structure_handle"] = _struct["structure_handle"]["handle"]
        return structure
    except KeyError as err:
        raise ResponseError(f"Failed to parse structure attributes: Missing key {err}")


def encode_value(parsed_tag: dict) -> bytes:
    """Encode a value for writing to the PLC.

    Args:
        parsed_tag: Parsed tag data with value to encode.

    Returns:
        bytes: Encoded value.

    Raises:
        RequestError: If encoding fails.
    """
    if isinstance(parsed_tag["value"], bytes):
        return parsed_tag["value"]
    try:
        value = parsed_tag["value"]
        elements = parsed_tag["elements"]
        data_type = parsed_tag["tag_info"]["data_type_name"]
        _type = parsed_tag["tag_info"]["type_class"]
        value_elements = parsed_tag["bool_elements"] or elements
        if data_type == "DWORD":
            if (parsed_tag.get("bit") or 0) % 32:
                raise RequestError("BOOL arrays only support writing full DWORDs, indexes must be multiples of 32")
            parsed_tag["elements"] = elements = elements - (parsed_tag["bit"] or 0) // 32
        if issubclass(_type, ArrayType):
            if value_elements > 1:
                if len(value) < value_elements:
                    raise RequestError(f"Insufficient data: expected {value_elements}, got {len(value)}")
                if len(value) > value_elements:
                    value = value[:value_elements]
            elif not isinstance(value, Sequence) or isinstance(value, str):
                value = [value]
            return _type.encode(value, value_elements)
        return _type.encode(value)
    except (ValueError, TypeError) as err:
        raise RequestError(f"Unable to encode value: {err}")


def _tag_return_size(tag_data: dict) -> int:
    """Calculate the expected return size of a tag read.

    Args:
        tag_data: Parsed tag data.

    Returns:
        int: Size in bytes.
    """
    tag_info = tag_data["tag_info"]
    if tag_info["tag_type"] == "atomic":
        size = DataTypes[tag_info["data_type"]].size
    else:
        size = tag_info["data_type"]["template"]["structure_size"]
    return size * tag_data["elements"]