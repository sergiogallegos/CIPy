=======
CIPy
=======

.. <<start>>

.. image:: https://img.shields.io/pypi/v/cipy.svg?style=for-the-badge
   :target: https://pypi.python.org/pypi/cipy
   :alt: PyPI Version

.. image:: https://img.shields.io/pypi/l/cipy.svg?style=for-the-badge
   :target: https://pypi.python.org/pypi/cipy
   :alt: License

.. image:: https://img.shields.io/pypi/pyversions/cipy.svg?style=for-the-badge
   :target: https://pypi.python.org/pypi/cipy
   :alt: Python Versions

|

.. image:: https://img.shields.io/pypi/dm/cipy?style=social
   :target: https://pypi.python.org/pypi/cipy
   :alt: Downloads

.. image:: https://img.shields.io/github/watchers/[your-username]/cipy?style=social
    :target: https://github.com/[your-username]/cipy
    :alt: Watchers

.. image:: https://img.shields.io/github/stars/[your-username]/cipy?style=social
    :target: https://github.com/[your-username]/cipy
    :alt: Stars

.. image:: https://img.shields.io/github/forks/[your-username]/cipy?style=social
    :target: https://github.com/[your-username]/cipy
    :alt: Forks

|

.. image:: https://readthedocs.org/projects/cipy/badge/?version=latest&style=for-the-badge
   :target: https://cipy.readthedocs.io/en/latest/
   :alt: Read the Docs

.. image:: https://img.shields.io/badge/gitmoji-%20%F0%9F%98%9C%20%F0%9F%98%8D-FFDD67.svg?style=for-the-badge
    :target: https://gitmoji.dev
    :alt: Gitmoji


Introduction
============

``CIPy`` is a Python library for communicating with industrial devices using the CIP (Control and Information Protocol) and EtherNet/IP protocols. It is derived from ``pycomm3``, which itself evolved from a Python 3 fork of ``pycomm``—a library for Allen-Bradley PLC communication. While building on the foundation of ``pycomm3``, ``CIPy`` introduces significant enhancements, including a more robust type system, complete path decoding, and a streamlined API. This project is tailored for users seeking reliable and flexible access to CIP-enabled devices, such as PLCs, drives, and meters.

The original ``pycomm`` and ``pycomm3`` projects laid the groundwork for this library, and their contributors' efforts are deeply appreciated. ``CIPy`` expands on their work with a focus on modern Python practices and extended functionality.

.. _pycomm: https://github.com/ruscito/pycomm
.. _pycomm3: https://github.com/ottowayi/pycomm3


Drivers
=======

``CIPy`` includes three drivers, inherited and enhanced from ``pycomm3``:

- `CIPDriver`_
    The core driver for CIP communication, handling connection management, device discovery, and generic messaging. It supports any EtherNet/IP device, including non-PLC hardware like drives and switches. Enhancements in ``CIPy`` include full ``EPATH`` decoding for complex routing.

- `LogixDriver`_
    Specialized for ControlLogix, CompactLogix, and Micro800 PLCs. Supports tag reading/writing, tag list uploads, and PLC time operations. Improved in ``CIPy`` with better structure handling and optimized packet management.

- `SLCDriver`_
    A legacy driver for SLC500 and MicroLogix PLCs, ported from ``pycomm3`` with minimal changes. Focuses on basic data file operations. Development is limited, but it remains functional.

.. _CIPDriver: https://cipy.readthedocs.io/en/latest/usage/cipdriver.html
.. _LogixDriver: https://cipy.readthedocs.io/en/latest/usage/logixdriver.html
.. _SLCDriver: https://cipy.readthedocs.io/en/latest/usage/slcdriver.html


Disclaimer
==========

PLCs and industrial devices can control critical or hazardous equipment. ``CIPy`` is provided "as is" with no guarantees of reliability in production environments. It does not claim complete or correct protocol implementation and should not be the sole dependency for critical systems. The library aims to provide convenient access to CIP devices for development and testing purposes.


Setup
=====

Install ``CIPy`` from PyPI using: ``pip install cipy`` or ``python -m pip install cipy``.

Optionally, configure logging with Python’s `logging`_ module. See the `Logging Section`_ in the docs for a simple setup utility.

.. _PyPI: https://pypi.org/project/cipy/
.. _logging: https://docs.python.org/3/library/logging.html
.. _Logging Section: https://cipy.readthedocs.io/en/latest/getting_started.html#logging


Python and OS Support
=====================

``CIPy`` is a Python 3-only library, supporting versions 3.6.1 to 3.11. It is designed to be OS-agnostic, running on any platform supported by Python. Development occurs primarily on Windows 10, with testing on Linux planned. Report OS-specific issues at the `GitHub repository`_.

.. attention::

    Python 3.6.0 is unsupported due to limitations in ``NamedTuple`` features fixed in 3.6.1.

.. _GitHub repository: https://github.com/[your-username]/cipy


Documentation
=============

This README provides an overview. Full documentation is available on `Read the Docs`_ or at `https://cipy.dev <https://cipy.dev>`_.

.. _Read the Docs: https://cipy.readthedocs.io/en/latest/


Contributions
=============

Contributions and issue reports are welcome! See the `Contributing`_ guidelines for details.

.. _Contributing: CONTRIBUTING.md


Highlighted Features
====================

- Enhanced ``generic_message`` for custom CIP operations, akin to Logix MSG instructions.
- Advanced type system:
    - Simplified Python types (e.g., ``str`` for strings, ``bool`` for BOOLs).
    - Full support for custom structs, arrays, and bit arrays.
    - Complete encoding/decoding for ``EPATH`` and path segments.
- Optimized packet handling for large or fragmented requests.

LogixDriver
-----------

- Unified ``read`` and ``write`` methods for all tag types.
- Automatic tag packing and fragmentation.
- Full structure support with dict-based values.
- Dynamic feature detection (e.g., Extended Forward Open, Symbol Instance Addressing).

CIPDriver Enhancements
----------------------

- Full ``EPATH`` decoding for complex CIP routing.
- Improved buffer management for performance.

LogixDriver Overview
====================

Initialize a driver with just a ``path`` (IP address, slot, or CIP route):

::

    from cipy import LogixDriver

    with LogixDriver('10.20.30.100/1') as plc:
        print(plc)
        # OUTPUT: Program Name: PLCA, Device: 1756-L83E/B, Revision: 28.13

        print(plc.info)
        # OUTPUT: {'vendor': 'Rockwell Automation/Allen-Bradley', ...}


Reading/Writing Tags
--------------------

The ``read`` and ``write`` methods are simple and versatile:

::

    with LogixDriver('10.20.30.100') as plc:
        # Reading
        plc.read('tag1', 'tag2', 'array{10}', 'string_tag', 'a_udt_tag')
        # Writing
        plc.write(('tag1', 42), ('array{5}', [1, 2, 3, 4, 5]), ('string_tag', 'Hello'))

        # Check results
        results = plc.read('tag1', 'tag2')
        for result in results:
            if result:
                print(f"{result.tag}: {result.value}")
            else:
                print(f"{result.tag} failed: {result.error}")


Unit Testing
============

``CIPy`` uses ``pytest`` for testing. Set the ``PLCPATH`` environment variable to your PLC’s address and run:

.. code-block::

    set PLCPATH=192.168.1.100
    pytest

Tests are a work in progress—contributions to improve coverage are encouraged!


License
=======

``CIPy`` is distributed under the MIT License. See the `LICENSE`_ file for details.

.. _LICENSE: LICENSE
