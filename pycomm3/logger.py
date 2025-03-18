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

"""Logging utilities for Pycomm3."""

import logging
import sys
from typing import Optional

__all__ = ["configure_default_logger", "LOG_VERBOSE"]

LOG_VERBOSE = 5  #: Custom logging level for verbose output (below DEBUG)


_logger = logging.getLogger("pycomm3")
_logger.addHandler(logging.NullHandler())


def _verbose(self: logging.Logger, msg: str, *args: Any, **kwargs: Any) -> None:
    """Log a message at the VERBOSE level."""
    if self.isEnabledFor(LOG_VERBOSE):
        self._log(LOG_VERBOSE, msg, args, **kwargs)


logging.addLevelName(LOG_VERBOSE, "VERBOSE")
logging.verbose = _verbose  # type: ignore[attr-defined]
logging.Logger.verbose = _verbose  # type: ignore[attr-defined]


def configure_default_logger(
    level: int = logging.INFO,
    filename: Optional[str] = None,
    logger: Optional[str] = None
) -> None:
    """Configure basic logging for Pycomm3.

    Args:
        level: Logging level (e.g., logging.INFO, LOG_VERBOSE). Default is INFO.
        filename: Optional file path to log to in addition to stdout.
        logger: Optional name of an additional logger to configure. Use '' for root logger.

    Example:
        >>> from pycomm3.logger import configure_default_logger, LOG_VERBOSE
        >>> configure_default_logger(level=LOG_VERBOSE, filename="pycomm3.log")
    """
    loggers = [logging.getLogger("pycomm3")]
    if logger == "":
        loggers.append(logging.getLogger())
    elif logger:
        loggers.append(logging.getLogger(logger))

    formatter = logging.Formatter(
        fmt="{asctime} [{levelname}] {name}.{funcName}(): {message}",
        style="{"
    )
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)

    if filename:
        file_handler = logging.FileHandler(filename, encoding="utf-8")
        file_handler.setFormatter(formatter)

    for log in loggers:
        log.setLevel(level)
        log.handlers = []  # Clear existing handlers to avoid duplicates
        log.addHandler(handler)
        if filename:
            log.addHandler(file_handler)