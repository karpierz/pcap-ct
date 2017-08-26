pcap-ct
=======

Python wrapper for the pcap library.

Overview
========

`Read the Docs <http://pcap-ct.rtfd.org>`__

TBD...

About original PyPCAP:
----------------------

Borrowed from the `original website <http://pypcap.readthedocs.org>`__:

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

The sample installation using `Chocolatey <https://chocolatey.org/>`_::

    choco install -y npcap --ia '/winpcap_mode=yes'

Requirements
============

This package requires:

- libpcap
- TBD...
- ATTENTION: currently works and tested only for Windows

Installation
============

Prerequisites:

+ Python 2.7 or higher or 3.3 or higher

  * http://www.python.org/
  * 2.7 and 3.4 are primary test environments.

+ pip and setuptools

  * http://pypi.python.org/pypi/pip
  * http://pypi.python.org/pypi/setuptools

To install run::

    python -m pip install --upgrade pcap-ct

Installation from sources:

Clone the `sources <https://github.com/karpierz/pcap-ct>`__ and run::

    python -m pip install ./pcap-ct

or on development mode:

    python -m pip install --editable ./pcap-ct

Development
===========

Visit `development page <https://github.com/karpierz/pcap-ct>`__

License
=======

  | Copyright (c) 2016-2017, Adam Karpierz
  |
  | Licensed under the BSD license
  | Please refer to the LICENSE file.

Authors
=======

* Adam Karpierz <python@python.pl>
