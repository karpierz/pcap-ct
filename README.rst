pcap-ct
=======

Python wrapper for the *pcap* library.

Overview
========

| Python |package_bold| package is a simplified object-oriented Python wrapper
  for *libpcap* C library - the current tcpdump.org version, and the WinPcap
  port for Windows..
|
| |package_bold| is a pure Python package, based on the low-level
  `libcap <https://pypi.org/project/libpcap/>`__ package.
| It is fully compliant implementation of the original
  `PyPCAP <https://github.com/pynetwork/pypcap>`__ 1.2.3 API (with some minor
  improvements and bug fixes) by implementing whole its functionality in a
  clean Python instead of Cython and C.

`PyPI record`_.

`Documentation`_.

About original PyPCAP:
----------------------

Borrowed from the `original website <https://pypcap.readthedocs.io>`__:

PyPCAP
------

This is a simplified object-oriented Python wrapper for libpcap -
the current tcpdump.org version, and the WinPcap port for Windows.

Example use::

    >>> import pcap
    >>> sniffer = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
    >>> addr = lambda pkt, offset: '.'.join(str(ord(pkt[i])) for i in range(offset, offset + 4))
    >>> for ts, pkt in sniffer:
    ...     print('%d\tSRC %-16s\tDST %-16s' % (ts, addr(pkt, sniffer.dloff + 12), addr(pkt, sniffer.dloff + 16)))
    ...

Windows notes
-------------

WinPcap has compatibility issues with Windows 10, therefore
it's recommended to use `Npcap <https://nmap.org/npcap/>`_
(Nmap's packet sniffing library for Windows, based on the WinPcap/Libpcap libraries,
but with improved speed, portability, security, and efficiency).
Please enable WinPcap API-compatible mode during the library installation.

Installation
============

Prerequisites:

+ Python 3.7 or higher

  * https://www.python.org/
  * 3.7 with C libpcap 1.8.1 is a primary test environment.
  * ATTENTION: currently tested only for Windows.

+ pip and setuptools

  * https://pypi.org/project/pip/
  * https://pypi.org/project/setuptools/

To install run:

  .. parsed-literal::

    python -m pip install --upgrade |package|

Development
===========

Prerequisites:

+ Development is strictly based on *tox*. To install it run::

    python -m pip install --upgrade tox

Visit `development page`_.

Installation from sources:

clone the sources:

  .. parsed-literal::

    git clone |respository| |package|

and run:

  .. parsed-literal::

    python -m pip install ./|package|

or on development mode:

  .. parsed-literal::

    python -m pip install --editable ./|package|

License
=======

  | Copyright (c) 2016-2022, Adam Karpierz
  | Licensed under the BSD license
  | https://opensource.org/licenses/BSD-3-Clause
  | Please refer to the accompanying LICENSE file.

Authors
=======

* Adam Karpierz <adam@karpierz.net>

.. |package| replace:: pcap-ct
.. |package_bold| replace:: **pcap-ct**
.. |respository| replace:: https://github.com/karpierz/pcap-ct.git
.. _development page: https://github.com/karpierz/pcap-ct
.. _PyPI record: https://pypi.org/project/pcap-ct/
.. _Documentation: https://pcap-ct.readthedocs.io/
