# Copyright (c) 2016-2022, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

"""\
packet capture library

This module provides a high level interface to packet capture systems.
All packets on the network, even those destined for other hosts, are
accessible through this mechanism.
"""

# Based on pcap.pyx

from typing import Optional, Tuple, List
import sys
import struct
import ctypes as ct

from libpcap import (DLT_NULL,   DLT_EN10MB, DLT_EN3MB,   DLT_AX25,
                     DLT_PRONET, DLT_CHAOS,  DLT_IEEE802, DLT_ARCNET,
                     DLT_SLIP,   DLT_PPP,    DLT_FDDI)
# XXX - Linux
from libpcap import (DLT_LINUX_SLL, DLT_LINUX_SLL2)

# XXX - OpenBSD
try:
    from libpcap import DLT_PFSYNC
except ImportError:
    DLT_PFSYNC =  18
from libpcap import DLT_PFLOG
from libpcap import DLT_RAW
from libpcap import DLT_LOOP
from libpcap import PCAP_D_INOUT, PCAP_D_IN, PCAP_D_OUT
from libpcap import PCAP_TSTAMP_PRECISION_MICRO, PCAP_TSTAMP_PRECISION_NANO

import libpcap as _pcap
from . import _pcap_ex

dltoff = {
    DLT_NULL:        4,
    DLT_EN10MB:     14,
    DLT_IEEE802:    22,
    DLT_ARCNET:      6,
    DLT_SLIP:       16,
    DLT_PPP:         4,
    DLT_FDDI:       21,
    DLT_PFLOG:      48,
    DLT_PFSYNC:      4,
    DLT_LOOP:        4,
    DLT_RAW:         0,
    DLT_LINUX_SLL:  16,
    DLT_LINUX_SLL2: 20,
}


class bpf:
    """bpf(filter, dlt=DLT_RAW) -> BPF filter object"""

    fcode = _pcap.bpf_program()

    def __init__(self, filter, dlt=DLT_RAW):  # noqa: A002 # char *filter
        """Initializer."""
        if _pcap_ex.compile_nopcap(65535, dlt, ct.byref(self.fcode),
                                   ct.c_char_p(filter), 1, 0) < 0:
            raise IOError("bad filter")

    def __del__(self):
        """Destructor."""
        _pcap.freecode(ct.byref(self.fcode))

    def filter(self, buf) -> bool:  # noqa: A003
        """Return boolean match for buf against our filter."""
        try:
            buf  = memoryview(buf).tobytes()
            size = len(buf)
        except:  # noqa: E722
            raise TypeError() from None
        return _pcap.bpf_filter(self.fcode.bf_insns,
                                ct.cast(ct.c_char_p(buf), ct.POINTER(ct.c_ubyte)),
                                size, size) != 0


class pcap:
    """pcap(name=None, snaplen=65535, promisc=True, timeout_ms=0,
            immediate=False, timestamp_in_ns=False, buffer_size=0,
            datalink=None) -> packet capture object

    Open a handle to a packet capture descriptor.

    Keyword arguments:
    name      -- name of a network interface or dumpfile to open,
                 or None to open the first available up interface
    snaplen   -- maximum number of bytes to capture for each packet
    promisc   -- boolean to specify promiscuous mode sniffing
    timeout_ms -- requests for the next packet will return None if the timeout
                  (in milliseconds) is reached and no packets were received
                  (Default: no timeout)
    immediate -- disable buffering, if possible
    timestamp_in_ns -- report timestamps in integer nanoseconds
    buffer_size -- set the buffer size (in bytes) for capture handle
                   (Default: 0 => use the platform's default)
    datalink -- manually set datalink type (eg for capture "any" interface,
                set to SLL2, will return interface where packet is captured)

    """

    def __init__(self, name=None, snaplen=65535, promisc=True,
                 timeout_ms=0, immediate=False, rfmon=False,
                 timestamp_in_ns=False, buffer_size=0, datalink=None):
        """Open a handle to a packet capture descriptor."""

        global dltoff

        self.__ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)

        if not name:
            cname = _pcap_ex.lookupdev(self.__ebuf)
            if cname is None:
                raise OSError(self.__ebuf.value.decode("utf-8", "ignore"))
        else:
            cname = name.encode("utf-8")

        try:
            _pcap.open_offline_with_tstamp_precision
        except AttributeError:
            self.__pcap = _pcap.open_offline(cname, self.__ebuf)
        else:
            self.__pcap = _pcap.open_offline_with_tstamp_precision(cname,
                                                                   PCAP_TSTAMP_PRECISION_NANO,
                                                                   self.__ebuf)
        if not self.__pcap:
            self.__pcap = _pcap.create(_pcap_ex.name(cname), self.__ebuf)

            def check_return(ret, descrip):
                if ret != 0:
                    raise OSError("{} failed to execute".format(descrip))

            check_return(_pcap.set_snaplen(self.__pcap, snaplen), "Set snaplength")
            check_return(_pcap.set_promisc(self.__pcap, promisc), "Set promiscuous mode")
            check_return(_pcap.set_timeout(self.__pcap, timeout_ms), "Set timeout")
            try:
                _pcap.set_immediate_mode
            except AttributeError as exc:
                if immediate: raise exc
            else:
                check_return(_pcap.set_immediate_mode(self.__pcap, immediate),
                                                      "Set immediate mode")
            try:
                _pcap.set_rfmon
            except AttributeError as exc:
                if rfmon: raise exc
            else:
                check_return(_pcap.set_rfmon(self.__pcap, rfmon), "Set monitor mode")
            check_return(_pcap.set_buffer_size(self.__pcap, buffer_size), "Set buffer size")
            # Ask for nano-second precision, but don't fail if not available.
            try:
                _pcap.set_tstamp_precision
            except AttributeError:
                pass
            else:
                _pcap.set_tstamp_precision(self.__pcap, PCAP_TSTAMP_PRECISION_NANO)

            if _pcap.activate(self.__pcap) != 0:
                raise OSError("Activateing packet capture failed. "
                              "Error returned by packet capture library "
                              "was {}".format(self.geterr()))
        if not self.__pcap:
            raise OSError(self.__ebuf.value.decode("utf-8", "ignore"))

        self.__name   = cname
        self.__filter = b""
        self.__timestamp_in_ns = timestamp_in_ns
        try:
            _pcap.get_tstamp_precision
        except AttributeError:
            precision = PCAP_TSTAMP_PRECISION_MICRO
        else:
            precision = _pcap.get_tstamp_precision(self.__pcap)
        if precision == PCAP_TSTAMP_PRECISION_MICRO:
            self.__precision_scale    = 1.0e-6
            self.__precision_scale_ns = 1000
        elif precision == PCAP_TSTAMP_PRECISION_NANO:
            self.__precision_scale    = 1.0e-9
            self.__precision_scale_ns = 1
        else:
            raise OSError("couldn't determine timestamp precision")

        if datalink is not None:
            _pcap.set_datalink(self.__pcap, datalink)

        try:
            self.__dloff = dltoff[_pcap.datalink(self.__pcap)]
        except KeyError:
            self.__dloff = 0  # <AK>: added

        if immediate and _pcap_ex.immediate(self.__pcap) < 0:
            raise OSError("couldn't enable immediate mode")

    def __del__(self):
        """Destructor."""
        try:
            if self.__pcap: _pcap.close(self.__pcap)
        except:  # noqa: E722
            pass

    @property
    def name(self) -> str:
        """Network interface or dumpfile name."""
        return self.__name.decode("utf-8")

    @property
    def snaplen(self):
        """Maximum number of bytes to capture for each packet."""
        return _pcap.snapshot(self.__pcap)

    @property
    def dloff(self):
        """Datalink offset (length of layer-2 frame header)."""
        return self.__dloff

    @property  # noqa: A003
    def filter(self) -> str:
        """Current packet capture filter."""
        return self.__filter.decode("utf-8")

    @property
    def fd(self):
        """File descriptor (or Win32 HANDLE) for capture handle."""
        return self.fileno()

    @property
    def precision(self):
        """Precision of timestamps"""
        try:
            _pcap.get_tstamp_precision
        except AttributeError:
            return PCAP_TSTAMP_PRECISION_MICRO
        return _pcap.get_tstamp_precision(self.__pcap)

    @property
    def timestamp_in_ns(self):
        """Whether timestamps are returned in nanosecond units"""
        return self.__timestamp_in_ns

    def fileno(self):
        """Return file descriptor (or Win32 HANDLE) for capture handle."""
        return _pcap_ex.fileno(self.__pcap)

    def close(self):
        """Explicitly close the underlying pcap handle"""
        if self.__pcap: _pcap.close(self.__pcap)  # <AK>: condition added
        self.__pcap = None

    def setfilter(self, value, optimize=1):
        """Set BPF-format packet capture filter."""
        fcode = _pcap.bpf_program()
        self.__filter = value.encode("utf-8")
        if _pcap.compile(self.__pcap, ct.byref(fcode), self.__filter, optimize, 0) < 0:
            raise OSError(self.geterr())
        if _pcap.setfilter(self.__pcap, ct.byref(fcode)) < 0:
            raise OSError(self.geterr())
        _pcap.freecode(ct.byref(fcode))

    def setdirection(self, direction) -> bool:
        """Set capture direction."""
        try:
            _pcap.setdirection
        except AttributeError:
            return False
        return _pcap.setdirection(self.__pcap, direction) == 0

    def setnonblock(self, nonblock=True):
        """Set non-blocking capture mode."""
        try:
            _pcap.setnonblock
        except AttributeError:
            return
        _pcap.setnonblock(self.__pcap, nonblock, self.__ebuf)

    def getnonblock(self) -> bool:
        """Return non-blocking capture mode as boolean."""
        try:
            _pcap.getnonblock
        except AttributeError:
            return False
        ret = _pcap.getnonblock(self.__pcap, self.__ebuf)
        if ret < 0:
            raise OSError(self.__ebuf.value.decode("utf-8", "ignore"))
        return ret != 0

    def datalink(self):
        """Return datalink type (DLT_* values)."""
        return _pcap.datalink(self.__pcap)

    def readpkts(self):
        """Return a list of (timestamp, packet) tuples received in one buffer."""
        pkts = []
        self.dispatch(-1, self.__add_pkts, pkts)
        return pkts

    def __add_pkts(self, ts, pkt, pkts):
        pkts.append((ts, pkt))

    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback,
        return the number of packets processed, or 0 for a savefile.

        Arguments:
        cnt      -- number of packets to process;
                    or 0 to process all packets until an error occurs,
                    EOF is reached, or the read times out;
                    or -1 to process all packets received in one buffer
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        ctx = _pcap_handler_ctx()
        ctx.scale           = self.__precision_scale
        ctx.scale_ns        = self.__precision_scale_ns
        ctx.timestamp_in_ns = self.__timestamp_in_ns
        ctx.callback        = callback
        ctx.args            = args
        ctx.exc             = None
        n = _pcap.dispatch(self.__pcap, cnt, _pcap_handler,
                           ct.cast(ct.pointer(ctx), ct.POINTER(ct.c_ubyte)))
        exc = ctx.exc
        if exc is not None:
            raise exc[0](exc[1]).with_traceback(exc[2])
        return n

    def sendpacket(self, buf) -> int:
        """Send a raw network packet on the interface."""
        if _pcap.sendpacket(self.__pcap,
                            ct.cast(ct.c_char_p(buf), ct.POINTER(ct.c_ubyte)),
                            len(buf)) == -1:
            raise OSError(self.geterr())
        return len(buf)

    def stats(self) -> Tuple:
        """Return a 3-tuple of the total number of packets received,
        dropped, and dropped by the interface.
        """
        pstat = _pcap.stat()
        if _pcap.stats(self.__pcap, ct.byref(pstat)) < 0:
            raise OSError(self.geterr())
        return (pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop)

    def loop(self, cnt, callback, *args):
        """Processing packets with a user callback during a loop.

        The loop can be exited when cnt value is reached
        or with an exception, including KeyboardInterrupt.

        Arguments:
        cnt      -- number of packets to process;
                    0 or -1 to process all packets until an error occurs,
                    EOF is reached;
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        scale    = self.__precision_scale
        scale_ns = self.__precision_scale_ns
        timestamp_in_ns = self.__timestamp_in_ns
        _pcap_ex.setup(self.__pcap)
        hdr  = _pcap.pkthdr()
        phdr = ct.pointer(hdr)
        pkt  = ct.POINTER(ct.c_ubyte)()
        i = 1
        while True:
            # with nogil:
            n = _pcap_ex.next_ex(self.__pcap, ct.byref(phdr), ct.byref(pkt))
            if n == 0:  # timeout
                continue
            elif n == 1:
                hdr = phdr[0]
                if timestamp_in_ns:
                    callback((hdr.ts.tv_sec * 1000000000) + (hdr.ts.tv_usec * scale_ns),
                             ct.cast(pkt, ct.POINTER(ct.c_char * hdr.caplen))[0].raw,
                             *args)
                else:
                    callback(hdr.ts.tv_sec + (hdr.ts.tv_usec * scale),
                             ct.cast(pkt, ct.POINTER(ct.c_char * hdr.caplen))[0].raw,
                             *args)
            elif n == -1:
                raise KeyboardInterrupt()
            elif n == -2:
                break
            # else:  # <AK>: added
            #   ??? what about other/unknown codes?
            if i == cnt: break
            i += 1

    def geterr(self) -> Optional[str]:
        """Return the last error message associated with this handle."""
        errmsg = _pcap.geterr(self.__pcap)
        return errmsg.decode("utf-8", "ignore") if errmsg is not None else None

    def __iter__(self):
        """Iterate over pcap."""
        _pcap_ex.setup(self.__pcap)
        return self

    def __next__(self):
        """Return the next item from the iterator"""
        scale    = self.__precision_scale
        scale_ns = self.__precision_scale_ns
        timestamp_in_ns = self.__timestamp_in_ns
        hdr  = _pcap.pkthdr()
        phdr = ct.pointer(hdr)
        pkt  = ct.POINTER(ct.c_ubyte)()
        while True:
            # with nogil:
            n = _pcap_ex.next_ex(self.__pcap, ct.byref(phdr), ct.byref(pkt))
            if n == 0:  # timeout
                continue
            elif n == 1:
                hdr = phdr[0]
                if timestamp_in_ns:
                    return ((hdr.ts.tv_sec * 1000000000) + (hdr.ts.tv_usec * scale_ns),
                            ct.cast(pkt, ct.POINTER(ct.c_char * hdr.caplen))[0].raw)
                else:
                    return (hdr.ts.tv_sec + (hdr.ts.tv_usec * scale),
                            ct.cast(pkt, ct.POINTER(ct.c_char * hdr.caplen))[0].raw)
            elif n == -1:
                raise KeyboardInterrupt()
            elif n == -2:
                raise StopIteration
            # else:  # <AK>: added
            #   ??? what about other/unknown codes?


def ex_name(foo: str) -> str:
    cname = foo.encode("utf-8")   # <AK>: added
    cname = _pcap_ex.name(cname)
    return cname.decode("utf-8")  # <AK>: added


def lookupdev() -> str:
    """Return the name of a network device suitable for sniffing."""
    ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
    name = _pcap_ex.lookupdev(ebuf)
    if name is None:
        raise OSError(ebuf.value.decode("utf-8", "ignore"))
    return name.decode("utf-8")


def findalldevs() -> List[str]:
    """Return a list of capture devices."""
    devs = ct.POINTER(_pcap.pcap_if_t)()
    ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
    status = _pcap.findalldevs(ct.byref(devs), ebuf)
    if status:
        raise OSError(ebuf.value.decode("utf-8", "ignore"))
    if not devs:
        return []
    retval = []
    try:  # <AK> added
        dev = devs
        while dev:
            dev = dev[0]
            retval.append(dev.name.decode("utf-8"))
            dev = dev.next
    finally:
        _pcap.freealldevs(devs)
    return retval


def lookupnet(dev: str) -> Tuple:
    """Return the address and the netmask of a given device
    as network-byteorder integers.
    """
    dev   = dev.encode("utf-8")  # <AK>: added
    netp  = ct.c_uint()
    maskp = ct.c_uint()
    ebuf  = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
    status = _pcap.lookupnet(dev, ct.byref(netp), ct.byref(maskp), ebuf)
    if status:
        raise OSError(ebuf.value.decode("utf-8", "ignore"))
    return (struct.pack("I", netp.value), struct.pack("I", maskp.value))


@_pcap.pcap_handler
def _pcap_handler(arg, hdr, pkt):  # with gil:
    ctx = ct.cast(arg, ct.POINTER(_pcap_handler_ctx))[0]
    try:
        hdr = hdr[0]
        scale    = ctx.scale
        scale_ns = ctx.scale_ns
        callback = ctx.callback
        args     = ctx.args
        if ctx.timestamp_in_ns:
            callback((hdr.ts.tv_sec * 1000000000) + (hdr.ts.tv_usec * scale_ns),
                     ct.cast(pkt, ct.POINTER(ct.c_char * hdr.caplen))[0].raw,
                     *args)
        else:
            callback(hdr.ts.tv_sec + (hdr.ts.tv_usec * scale),
                     ct.cast(pkt, ct.POINTER(ct.c_char * hdr.caplen))[0].raw,
                     *args)
    except:  # noqa: E722
        ctx.exc = sys.exc_info()


class _pcap_handler_ctx(ct.Structure):
    _fields_ = [
    ("scale",           ct.c_double),
    ("scale_ns",        ct.c_longlong),
    ("timestamp_in_ns", ct.c_bool),
    ("callback",        ct.py_object),
    ("args",            ct.py_object),
    ("exc",             ct.py_object),
]
