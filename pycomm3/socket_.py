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

"""Socket wrapper for CIP communication in Pycomm3."""

import logging
import socket
import struct
from typing import Optional

from .exceptions import CommError
from .const import HEADER_SIZE

__all__ = ["Socket"]


class Socket:
    """Wrapper around a TCP socket for Ethernet/IP communication.

    Attributes:
        sock: Underlying socket object.
    """

    __log = logging.getLogger(f"{__module__}.{__qualname__}")

    def __init__(self, timeout: float = 5.0) -> None:
        """Initialize the socket with a timeout.

        Args:
            timeout: Socket timeout in seconds (default: 5.0).
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    def connect(self, host: str, port: int) -> None:
        """Connect to a host and port.

        Args:
            host: Hostname or IP address.
            port: Port number.

        Raises:
            CommError: If connection fails.
        """
        try:
            self.sock.connect((socket.gethostbyname(host), port))
            self.__log.debug(f"Connected to {host}:{port}")
        except socket.error as err:
            raise CommError(f"Failed to connect to {host}:{port}") from err

    def send(self, msg: bytes, timeout: float = 0) -> int:
        """Send a message over the socket.

        Args:
            msg: Message bytes to send.
            timeout: Optional override timeout in seconds (0 to keep default).

        Returns:
            int: Number of bytes sent.

        Raises:
            CommError: If sending fails or connection is broken.
        """
        if timeout != 0:
            self.sock.settimeout(timeout)
        total_sent = 0
        while total_sent < len(msg):
            try:
                sent = self.sock.send(msg[total_sent:])
                if sent == 0:
                    raise CommError("Socket connection broken during send")
                total_sent += sent
            except socket.error as err:
                raise CommError("Socket connection broken during send") from err
        self.__log.debug(f"Sent {total_sent} bytes")
        return total_sent

    def receive(self, timeout: float = 0) -> bytes:
        """Receive a message from the socket.

        Args:
            timeout: Optional override timeout in seconds (0 to keep default).

        Returns:
            bytes: Received data.

        Raises:
            CommError: If receiving fails or connection is broken.
        """
        try:
            if timeout != 0:
                self.sock.settimeout(timeout)
            data = self.sock.recv(256)
            if not data:
                raise CommError("Socket connection broken: no data received")
            data_len = struct.unpack_from("<H", data, 2)[0]
            while len(data) - HEADER_SIZE < data_len:
                chunk = self.sock.recv(256)
                if not chunk:
                    raise CommError("Socket connection broken: incomplete data")
                data += chunk
            self.__log.debug(f"Received {len(data)} bytes")
            return data
        except socket.error as err:
            raise CommError("Socket connection broken during receive") from err

    def close(self) -> None:
        """Close the socket connection."""
        try:
            self.sock.close()
            self.__log.debug("Socket closed")
        except socket.error as err:
            self.__log.warning(f"Error closing socket: {err}")