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
import ipaddress
import logging
import socket
from functools import wraps
from os import urandom
from typing import Any, Dict, List, Optional, Sequence, Tuple, Type, Union

from .cip import (
    ConnectionManagerInstances,
    ClassCode,
    CIPSegment,
    ConnectionManagerServices,
    Services,
    PortSegment,
    PADDED_EPATH,
    DataType,
    UDINT,
    UINT,
)
from .const import (
    PRIORITY,
    TIMEOUT_MULTIPLIER,
    TIMEOUT_TICKS,
    TRANSPORT_CLASS,
    MSG_ROUTER_PATH,
)
from .custom_types import ModuleIdentityObject
from .exceptions import ResponseError, CommError, RequestError
from .packets import (
    RequestPacket,
    ResponsePacket,
    PacketLazyFormatter,
    ListIdentityRequestPacket,
    RegisterSessionRequestPacket,
    UnRegisterSessionRequestPacket,
    GenericConnectedRequestPacket,
    GenericUnconnectedRequestPacket,
)
from .socket_ import Socket
from .tag import Tag
from .util import cycle

__all__ = [
    "CIPDriver",
    "with_forward_open",
    "parse_connection_path",
]


def with_forward_open(func):
    """Decorator to ensure a forward open request has been completed with the PLC.

    Args:
        func: The function to wrap.

    Returns:
        Callable: Wrapped function that checks for a forward open connection.

    Raises:
        ResponseError: If the connection cannot be opened.
    """

    @wraps(func)
    def wrapped(self: CIPDriver, *args, **kwargs):
        if self._target_is_connected:
            return func(self, *args, **kwargs)

        logger = logging.getLogger("pycomm3.cip_driver")
        opened = False
        if self._cfg["extended forward open"]:
            logger.info("Attempting an Extended Forward Open...")
            if self._forward_open():
                opened = True
            else:
                logger.info("Extended Forward Open failed, attempting standard Forward Open.")
                self._cfg["extended forward open"] = False
                self._cfg["connection_size"] = 500
                if self._forward_open():
                    opened = True
        else:
            opened = self._forward_open()

        if not opened:
            raise ResponseError(f"Target did not connect. {func.__name__} will not be executed.")
        return func(self, *args, **kwargs)

    return wrapped


class CIPDriver:
    """A base CIP driver for SLCDriver and LogixDriver classes.

    Implements common CIP services such as session registration, forward open/close, and generic messaging.
    Provides a foundation for Ethernet/IP communication with PLCs.

    Attributes:
        connected (bool): Indicates if a connection is open.
        connection_size (int): CIP connection size (4000 for Extended Forward Open, 500 otherwise).
        socket_timeout (float): Socket connection timeout in seconds.
        info (dict): Device information retrieved from the PLC.

    Example:
        >>> driver = CIPDriver("10.20.30.100")
        >>> driver.open()
        >>> driver.close()
    """

    __log = logging.getLogger(f"{__module__}.{__qualname__}")
    _auto_slot_cip_path = False

    def __init__(self, path: str, *args, **kwargs: Any) -> None:
        """Initialize the CIPDriver.

        Args:
            path: CIP path to the target PLC (e.g., "10.20.30.100", "10.20.30.100/1").
            *args: Additional positional arguments (unused).
            **kwargs: Additional keyword arguments for configuration overrides.

        Raises:
            RequestError: If the path is malformed or invalid.
        """
        self._sequence = cycle(65535, start=1)
        self._sock: Optional[Socket] = None
        self._session: int = 0
        self._connection_opened: bool = False
        self._target_cid: Optional[bytes] = None
        self._target_is_connected: bool = False
        self._info: Dict[str, Any] = {}
        self._cip_path = path
        ip, port, _path = parse_connection_path(path, self._auto_slot_cip_path)

        self._cfg = {
            "context": b"_pycomm_",
            "protocol version": b"\x01\x00",
            "rpi": 5000,
            "port": port or 44818,
            "timeout": 10,
            "ip address": ip,
            "cip_path": _path,
            "option": 0,
            "cid": b"\x27\x04\x19\x71",
            "csn": b"\x27\x04",
            "vid": b"\x09\x10",
            "vsn": b"\x09\x10\x19\x71",
            "extended forward open": True,
            "connection_size": 4000,
            "socket_timeout": 5.0,
        }
        self._cfg.update(kwargs)
        self.__log.debug(f"Initialized with path={path}, config={self._cfg}")

    def __enter__(self) -> CIPDriver:
        """Context manager entry point."""
        self.open()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        """Context manager exit point.

        Args:
            exc_type: Exception type, if any.
            exc_val: Exception value, if any.
            exc_tb: Exception traceback, if any.

        Returns:
            bool: True if no exception occurred, False otherwise.
        """
        try:
            self.close()
        except CommError as err:
            self.__log.exception(f"Error closing connection: {err}")
            return False
        else:
            if not exc_type:
                return True
            self.__log.exception("Unhandled Client Error", exc_info=(exc_type, exc_val, exc_tb))
            return False

    def __repr__(self) -> str:
        """Detailed string representation of the driver."""
        return f"{self.__class__.__name__}(path={self._cip_path!r})"

    def __str__(self) -> str:
        """Human-readable string representation of the driver."""
        _rev = self._info.get("revision", {"major": -1, "minor": -1})
        return f"Device: {self._info.get('product_type', 'None')}, Revision: {_rev['major']}.{_rev['minor']}"

    @property
    def connected(self) -> bool:
        """Check if a connection is currently open.

        Returns:
            bool: True if connected, False otherwise.
        """
        return self._connection_opened

    @property
    def connection_size(self) -> int:
        """CIP connection size.

        Returns:
            int: 4000 if using Extended Forward Open, 500 otherwise.
        """
        return self._cfg["connection_size"]

    @property
    def socket_timeout(self) -> float:
        """Socket connection timeout in seconds.

        Returns:
            float: Current timeout value.
        """
        return self._cfg["socket_timeout"]

    @socket_timeout.setter
    def socket_timeout(self, value: float) -> None:
        """Set the socket connection timeout.

        Args:
            value: Timeout in seconds.
        """
        self._cfg["socket_timeout"] = value

    @property
    def info(self) -> Dict[str, Any]:
        """Device information retrieved from the PLC.

        Returns:
            dict: Information dictionary.
        """
        return self._info

    @classmethod
    def list_identity(cls, path: str) -> Optional[Dict[str, Any]]:
        """Identify the target device using the ListIdentity service.

        Args:
            path: CIP path to the target device.

        Returns:
            dict | None: Device identity if successful, None otherwise.
        """
        plc = cls(path)
        try:
            plc.open()
            identity = plc._list_identity()
        finally:
            plc.close()
        return identity

    @classmethod
    def discover(cls, broadcast_address: str = "255.255.255.255") -> List[Dict[str, Any]]:
        """Discover available devices on the current network(s).

        Args:
            broadcast_address: Broadcast address to use (default: "255.255.255.255").

        Returns:
            list[dict]: List of discovered device identities.
        """
        cls.__log.info("Discovering devices...")
        ip_addrs = [
            sockaddr[0]
            for family, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None)
            if family == socket.AF_INET
        ]

        driver = CIPDriver("0.0.0.0")  # Dummy driver for request creation
        request = ListIdentityRequestPacket()
        message = request.build_request(None, driver._session, b"\x00" * 8, 0)
        devices = []

        for ip in ip_addrs:
            cls.__log.debug(f"Broadcasting discover for IP: {ip}")
            devices.extend(cls._broadcast_discover(ip, message, request, broadcast_address))

        if not devices:
            cls.__log.debug("No devices found, attempting broadcast without binding.")
            devices.extend(cls._broadcast_discover(None, message, request, broadcast_address))

        cls.__log.info(f"Discovered {len(devices)} device(s): {devices!r}" if devices else "No devices discovered")
        return devices

    @classmethod
    def _broadcast_discover(cls, ip: Optional[str], message: bytes, request: RequestPacket, broadcast_address: str) -> List[Dict[str, Any]]:
        """Broadcast a discovery request and collect responses.

        Args:
            ip: Local IP to bind to, or None for no binding.
            message: Discovery request message.
            request: Request packet for response parsing.
            broadcast_address: Broadcast address to send to.

        Returns:
            list[dict]: List of device identities.
        """
        devices = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if ip:
                sock.bind((ip, 0))

            sock.sendto(message, (broadcast_address, 44818))

            while True:
                try:
                    resp = sock.recv(4096)
                    response = request.response_class(request, resp)
                    if response:
                        devices.append(response.identity)
                except socket.timeout:
                    break
        except Exception as err:
            cls.__log.exception(f"Error broadcasting discover request: {err}")
        finally:
            return devices

    def _list_identity(self) -> Optional[Dict[str, Any]]:
        """Send a ListIdentity request to the target.

        Returns:
            dict | None: Device identity if successful, None otherwise.
        """
        request = ListIdentityRequestPacket()
        response = self.send(request)
        return response.identity if response else None

    def get_module_info(self, slot: int) -> Dict[str, Any]:
        """Get the Identity object for a given slot in the rack.

        Args:
            slot: Slot number in the rack.

        Returns:
            dict: Module identity information.

        Raises:
            ResponseError: If the request fails.
        """
        try:
            route_path = PADDED_EPATH.encode(
                (*self._cfg["cip_path"][:-1], PortSegment("bp", slot)),
                length=True,
                pad_length=True,
            )
            response = self.generic_message(
                service=Services.get_attributes_all,
                class_code=ClassCode.identity_object,
                instance=b"\x01",
                connected=False,
                unconnected_send=True,
                route_path=route_path,
                name=f"get_module_info_slot_{slot}",
            )
            if response and not response.error:
                return ModuleIdentityObject.decode(response.value)
            raise ResponseError(f"Failed to get module info: {response.error}")
        except Exception as err:
            raise ResponseError(f"Error getting module info for slot {slot}") from err

    def open(self) -> bool:
        """Open a new Ethernet/IP connection and register a CIP session.

        Returns:
            bool: True if successful, False otherwise.

        Raises:
            CommError: If the connection or session registration fails.
        """
        if self._connection_opened:
            return True
        try:
            if self._sock is None:
                self._sock = Socket(self._cfg["socket_timeout"])
            self.__log.debug(f"Opening connection to {self._cfg['ip address']}:{self._cfg['port']}")
            self._sock.connect(self._cfg["ip address"], self._cfg["port"])
            self._connection_opened = True
            self._cfg["cid"] = urandom(4)
            self._cfg["vsn"] = urandom(4)
            session = self._register_session()
            if session is None:
                raise CommError("Session registration failed")
            return True
        except Exception as err:
            self._connection_opened = False
            raise CommError("Failed to open connection") from err

    def _register_session(self) -> Optional[int]:
        """Register a new CIP session with the target.

        Returns:
            int | None: Session ID if successful, None otherwise.
        """
        if self._session:
            return self._session

        request = RegisterSessionRequestPacket(self._cfg["protocol version"])
        response = self.send(request)
        if response and not response.error:
            self._session = response.session
            self.__log.info(f"Session registered: {self._session}")
            return self._session
        self.__log.error(f"Failed to register session: {response.error if response else 'No response'}")
        return None

    def _forward_open(self) -> bool:
        """Open a connection with the target PLC using Forward Open or Extended Forward Open.

        Returns:
            bool: True if successful, False otherwise.

        Raises:
            CommError: If no session is registered.
        """
        if self._target_is_connected:
            return True
        if not self._session:
            raise CommError("A session must be registered before a Forward Open")

        init_net_params = 0b_0100_0010_0000_0000  # CIP Vol 1 - 3-5.5.1.1
        net_params = (
            UDINT.encode((self.connection_size & 0xFFFF) | (init_net_params << 16))
            if self._cfg["extended forward open"]
            else UINT.encode((self.connection_size & 0x01FF) | init_net_params)
        )
        route_path = PADDED_EPATH.encode(self._cfg["cip_path"] + MSG_ROUTER_PATH, length=True)
        service = (
            ConnectionManagerServices.large_forward_open
            if self._cfg["extended forward open"]
            else ConnectionManagerServices.forward_open
        )

        forward_open_msg = [
            PRIORITY,
            TIMEOUT_TICKS,
            b"\x00\x00\x00\x00",  # O->T connection ID
            self._cfg["cid"],
            self._cfg["csn"],
            self._cfg["vid"],
            self._cfg["vsn"],
            TIMEOUT_MULTIPLIER,
            b"\x00\x00\x00",  # reserved
            b"\x01\x40\x20\x00",  # O->T RPI (fixed value)
            net_params,
            b"\x01\x40\x20\x00",  # T->O RPI
            net_params,
            TRANSPORT_CLASS,
        ]

        response = self.generic_message(
            service=service,
            class_code=ClassCode.connection_manager,
            instance=ConnectionManagerInstances.open_request,
            request_data=b"".join(forward_open_msg),
            route_path=route_path,
            connected=False,
            name="forward_open",
        )

        if response and not response.error:
            self._target_cid = response.value[:4]
            self._target_is_connected = True
            self.__log.info(
                f"{'Extended ' if self._cfg['extended forward open'] else ''}Forward Open succeeded. Target CID={self._target_cid}"
            )
            return True
        self.__log.error(f"Forward Open failed: {response.error if response else 'No response'}")
        return False

    def close(self) -> None:
        """Close the current connection and unregister the session.

        Raises:
            CommError: If closing the connection or session fails.
        """
        errors = []
        try:
            if self._target_is_connected:
                self._forward_close()
            if self._session:
                self._un_register_session()
        except Exception as err:
            errors.append(str(err))
            self.__log.exception("Error closing connection with device")

        try:
            if self._sock:
                self._sock.close()
        except Exception as err:
            errors.append(str(err))
            self.__log.exception("Error closing socket connection")

        self._sock = None
        self._target_is_connected = False
        self._session = 0
        self._connection_opened = False

        if errors:
            raise CommError("Errors during close: " + " - ".join(errors))

    def _un_register_session(self) -> None:
        """Unregister the current session with the target."""
        request = UnRegisterSessionRequestPacket()
        self.send(request)
        self._session = 0
        self.__log.info("Session unregistered")

    def _forward_close(self) -> bool:
        """Close the current connection using the Forward Close service.

        Returns:
            bool: True if successful, False otherwise.

        Raises:
            CommError: If no session is registered.
        """
        if not self._session:
            raise CommError("A session must be registered before a Forward Close")

        route_path = PADDED_EPATH.encode(self._cfg["cip_path"] + MSG_ROUTER_PATH, length=True, pad_length=True)
        forward_close_msg = [
            PRIORITY,
            TIMEOUT_TICKS,
            self._cfg["csn"],
            self._cfg["vid"],
            self._cfg["vsn"],
        ]

        response = self.generic_message(
            service=ConnectionManagerServices.forward_close,
            class_code=ClassCode.connection_manager,
            instance=ConnectionManagerInstances.open_request,
            connected=False,
            route_path=route_path,
            request_data=b"".join(forward_close_msg),
            name="forward_close",
        )

        if response and not response.error:
            self._target_is_connected = False
            self.__log.info("Forward Close succeeded")
            return True
        self.__log.error(f"Forward Close failed: {response.error if response else 'No response'}")
        return False

    def generic_message(
        self,
        service: Union[int, bytes],
        class_code: Union[int, bytes],
        instance: Union[int, bytes],
        attribute: Union[int, bytes] = b"",
        request_data: Any = b"",
        data_type: Optional[Union[Type[DataType], DataType]] = None,
        name: str = "generic",
        connected: bool = True,
        unconnected_send: bool = False,
        route_path: Union[bool, Sequence[CIPSegment], bytes, str] = True,
        **kwargs: Any,
    ) -> Tag:
        """Perform a generic CIP message, similar to MSG instructions in Logix.

        Args:
            service: Service code for the request (single byte).
            class_code: Request object class ID.
            instance: ID for an instance of the class (0 for class attributes).
            attribute: Attribute ID for the service/class/instance (optional).
            request_data: Additional data required for the request (optional).
            data_type: DataType class to decode the response, None for raw bytes.
            name: Arbitrary name for tracking the returned Tag.
            connected: True if a CIP connection is required, False for UCMM.
            unconnected_send: Wrap service in an UnconnectedSend service (unconnected only).
            route_path: True for current route, False to ignore, or custom path (str, bytes, or segments).
            **kwargs: Additional arguments (e.g., return_response_packet).

        Returns:
            Tag: Result of the request.

        Raises:
            ResponseError: If the message fails and no response is returned.
        """
        if connected:
            with_forward_open(lambda _: None)(self)

        request_args = {
            "service": service,
            "class_code": class_code,
            "instance": instance,
            "attribute": attribute,
            "request_data": request_data,
            "data_type": data_type,
        }

        if connected:
            request_args["sequence"] = self._sequence
        else:
            if route_path is True:
                request_args["route_path"] = PADDED_EPATH.encode(self._cfg["cip_path"], length=True, pad_length=True)
            elif isinstance(route_path, str):
                request_args["route_path"] = PADDED_EPATH.encode(parse_cip_route(route_path), length=True, pad_length=True)
            elif isinstance(route_path, bytes):
                request_args["route_path"] = route_path
            elif route_path:
                request_args["route_path"] = PADDED_EPATH.encode(route_path, length=True, pad_length=True)
            request_args["unconnected_send"] = unconnected_send

        req_class = GenericConnectedRequestPacket if connected else GenericUnconnectedRequestPacket
        request = req_class(**request_args)

        self.__log.info(f"Sending generic message: {name}")
        response = self.send(request)
        if not response or response.error:
            self.__log.error(f"Generic message '{name}' failed: {response.error if response else 'No response'}")
        else:
            self.__log.info(f"Generic message '{name}' completed")

        return (
            Tag(name, response, data_type, error=response.error)
            if kwargs.get("return_response_packet")
            else Tag(name, response.value if response else None, data_type, error=response.error if response else "No response")
        )

    def send(self, request: RequestPacket) -> ResponsePacket:
        """Send a request packet to the PLC and return the response.

        Args:
            request: The request packet to send.

        Returns:
            ResponsePacket: The response from the PLC.

        Raises:
            CommError: If sending or receiving fails.
        """
        if not request.error:
            request_kwargs = {
                "target_cid": self._target_cid,
                "session_id": self._session,
                "context": self._cfg["context"],
                "option": self._cfg["option"],
                "sequence": self._sequence,
            }
            self._send(request.build_request(**request_kwargs))
            self.__log.debug(f"Sent: {request!r}")
            reply = None if request.no_response else self._receive()
        else:
            reply = None

        response = request.response_class(request, reply)
        self.__log.debug(f"Received: {response!r}")
        return response

    def _send(self, message: bytes) -> None:
        """Send a message over the socket.

        Args:
            message: The message to send.

        Raises:
            CommError: If sending fails.
        """
        try:
            self.__log.verbose(">>> SEND >>> \n%s", PacketLazyFormatter(message))
            if self._sock:
                self._sock.send(message)
        except Exception as err:
            raise CommError("Failed to send message") from err

    def _receive(self) -> bytes:
        """Receive a reply from the socket.

        Returns:
            bytes: The received data.

        Raises:
            CommError: If receiving fails.
        """
        try:
            if self._sock:
                reply = self._sock.receive()
                self.__log.verbose("<<< RECEIVE <<< \n%s", PacketLazyFormatter(reply))
                return reply
            raise CommError("Socket not initialized")
        except Exception as err:
            raise CommError("Failed to receive reply") from err


def parse_connection_path(path: str, auto_slot: bool = False) -> Tuple[str, Optional[int], List[PortSegment]]:
    """Parse and validate a CIP path into IP, port, and segments.

    Args:
        path: CIP path (e.g., "10.20.30.100", "10.20.30.100:44818/1").
        auto_slot: If True, appends a default slot if not specified.

    Returns:
        tuple: (IP address, port, list of PortSegments).

    Raises:
        RequestError: If the path is invalid.
    """
    try:
        path = path.replace("\\", "/").replace(",", "/")
        ip, *route = path.split("/")
        port = None
        if ":" in ip:
            ip, port_str = ip.split(":")
            port = int(port_str)
            if not 0 < port < 65535:
                raise RequestError(f"Invalid port: {port}")
        ipaddress.ip_address(ip)  # Validate IP
        _path = parse_cip_route(route, auto_slot)
        return ip, port, _path
    except ValueError as err:
        raise RequestError(f"Failed to parse connection path '{path}': {err}")
    except Exception as err:
        raise RequestError(f"Failed to parse connection path '{path}'") from err


def parse_cip_route(path: Union[str, List[str]], auto_slot: bool = False) -> List[PortSegment]:
    """Parse a CIP route into a list of PortSegments.

    Args:
        path: Route string or list of segments (e.g., "1/0" or ["1", "0"]).
        auto_slot: If True, appends a default slot if path is empty or single.

    Returns:
        list[PortSegment]: Parsed route segments.

    Raises:
        RequestError: If the route is invalid.
    """
    try:
        if isinstance(path, str):
            segments = path.split("/")
        else:
            segments = path

        if not segments:
            return [PortSegment("bp", 0)] if auto_slot else []
        if len(segments) == 1 and auto_slot:
            return [PortSegment("bp", segments[0])]

        if len(segments) % 2:
            raise RequestError(f"Invalid CIP route '{path}': Must contain port/link pairs, got {len(segments)} segments")

        pairs = (segments[i:i + 2] for i in range(0, len(segments), 2))
        return [PortSegment(int(port) if port.isdigit() else port, link) for port, link in pairs]
    except Exception as err:
        raise RequestError(f"Failed to parse CIP route '{path}'") from err