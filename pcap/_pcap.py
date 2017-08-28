"""\
packet capture library

This module provides a high level interface to packet capture systems.
All packets on the network, even those destined for other hosts, are
accessible through this mechanism.
"""

# Based on pcap.pyx

from __future__ import absolute_import

import sys
import struct
import ctypes as ct

from libpcap import (DLT_NULL,   DLT_EN10MB, DLT_EN3MB,   DLT_AX25,
                     DLT_PRONET, DLT_CHAOS,  DLT_IEEE802, DLT_ARCNET,
                     DLT_SLIP,   DLT_PPP,    DLT_FDDI)
# XXX - Linux
from libpcap import DLT_LINUX_SLL
# XXX - OpenBSD
try:
    from libpcap import DLT_PFSYNC
except ImportError:
    DLT_PFSYNC =  18
from libpcap import DLT_PFLOG
from libpcap import DLT_RAW
from libpcap import DLT_LOOP
from libpcap import PCAP_D_INOUT, PCAP_D_IN, PCAP_D_OUT

import libpcap as _pcap
from . import _pcap_ex

dltoff = {
    DLT_NULL:       4,
    DLT_EN10MB:    14,
    DLT_IEEE802:   22,
    DLT_ARCNET:     6,
    DLT_SLIP:      16,
    DLT_PPP:        4,
    DLT_FDDI:      21,
    DLT_PFLOG:     48,
    DLT_PFSYNC:     4,
    DLT_LOOP:       4,
    DLT_RAW:        0,
    DLT_LINUX_SLL: 16,
}


class bpf(object):

    """bpf(filter, dlt=DLT_RAW) -> BPF filter object"""

    fcode = _pcap.bpf_program()

    def __init__(self, filter, dlt=DLT_RAW): # char *filter

        if _pcap_ex.compile_nopcap(65535, dlt, ct.byref(self.fcode),
                                   ct.c_char_p(filter), 1, 0) < 0:
            raise IOError("bad filter")

    def __del__(self):

        _pcap.freecode(ct.byref(self.fcode))

    def filter(self, buf):

        """Return boolean match for buf against our filter."""

        try:
            buf  = memoryview(buf).tobytes()
            size = len(buf)
        except:
            raise TypeError()
        return _pcap.bpf_filter(self.fcode.bf_insns,
                                ct.cast(ct.c_char_p(buf), ct.POINTER(ct.c_ubyte)),
                                size, size) != 0


class pcap(object):

    """pcap(name=None, snaplen=65535, promisc=True, timeout_ms=None, immediate=False)  -> packet capture object

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
    """

    def __init__(self, name=None, snaplen=65535, promisc=True,
                 timeout_ms=0, immediate=False):

        global dltoff

        self.__ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)

        if not name:
            cname = _pcap_ex.lookupdev(self.__ebuf)
            if cname is None:
                raise OSError(str(self.__ebuf.value.decode("utf-8", "ignore")))
        else:
            cname = name.encode("utf-8")

        self.__pcap = _pcap.open_offline(cname, self.__ebuf)
        if not self.__pcap:
            self.__pcap = _pcap.open_live(_pcap_ex.name(cname), snaplen, promisc,
                                          timeout_ms, self.__ebuf)
        if not self.__pcap:
            raise OSError(str(self.__ebuf.value.decode("utf-8", "ignore")))

        self.__name   = cname
        self.__filter = b""
        try:
            self.__dloff = dltoff[_pcap.datalink(self.__pcap)]
        except KeyError:
            self.__dloff = 0  # AK: added

        if immediate and _pcap_ex.immediate(self.__pcap) < 0:
            raise OSError("couldn't enable immediate mode")

    def __del__(self):

        try:
            if self.__pcap: _pcap.close(self.__pcap)
        except:
            pass

    @property
    def name(self):

        """Network interface or dumpfile name."""

        return str(self.__name.decode("utf-8"))

    @property
    def snaplen(self):

        """Maximum number of bytes to capture for each packet."""

        return _pcap.snapshot(self.__pcap)

    @property
    def dloff(self):

        """Datalink offset (length of layer-2 frame header)."""

        return self.__dloff

    @property
    def filter(self):

        """Current packet capture filter."""

        return str(self.__filter.decode("utf-8"))

    @property
    def fd(self):

        """File descriptor (or Win32 HANDLE) for capture handle."""

        return self.fileno()

    def fileno(self):

        """Return file descriptor (or Win32 HANDLE) for capture handle."""

        return _pcap_ex.fileno(self.__pcap)

    def setfilter(self, value, optimize=1):

        """Set BPF-format packet capture filter."""

        fcode = _pcap.bpf_program()
        self.__filter = value.encode("utf-8")
        if _pcap.compile(self.__pcap, ct.byref(fcode), self.__filter, optimize, 0) < 0:
            raise OSError(self.geterr())
        if _pcap.setfilter(self.__pcap, ct.byref(fcode)) < 0:
            raise OSError(self.geterr())
        _pcap.freecode(ct.byref(fcode))

    def setdirection(self, direction):

        """Set capture direction."""

        return _pcap_ex.setdirection(self.__pcap, direction) == 0

    def setnonblock(self, nonblock=True):

        """Set non-blocking capture mode."""

        _pcap_ex.setnonblock(self.__pcap, nonblock, self.__ebuf)

    def getnonblock(self):

        """Return non-blocking capture mode as boolean."""

        ret = _pcap_ex.getnonblock(self.__pcap, self.__ebuf)
        if ret < 0:
            raise OSError(str(self.__ebuf.value.decode("utf-8", "ignore")))
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
        ctx.callback = callback
        ctx.args     = args
        ctx.exc      = None
        n = _pcap.dispatch(self.__pcap, cnt, _pcap_handler,
                           ct.cast(ct.pointer(ctx), ct.POINTER(ct.c_ubyte)))
        exc = ctx.exc
        if exc is not None:
            if sys.version_info[0] < 3:
                raise exc[0](exc[1])
            else:
                raise exc[0](exc[1]).with_traceback(exc[2])
        return n

    def sendpacket(self, buf):

        """Send a raw network packet on the interface."""

        if _pcap.sendpacket(self.__pcap, buf, len(buf)) == -1:
            raise OSError(self.geterr())
        return len(buf)

    def stats(self):

        """Return a 3-tuple of the total number of packets received,
        dropped, and dropped by the interface."""

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

        _pcap_ex.setup(self.__pcap)

        i = 1
        while True:
            # with nogil:
            n, hdr, pkt = _pcap_ex.next(self.__pcap)
            if n == 0:  # timeout
                continue
            elif n == 1:
                header = hdr[0]
                callback(header.ts.tv_sec + (header.ts.tv_usec / 1000000.0),
                         ct.cast(pkt, ct.POINTER(ct.c_char * header.caplen))[0].raw,
                         *args)
            elif n == -1:
                raise KeyboardInterrupt()
            elif n == -2:
                break
            #else:  # AK: added
            #   ??? what about other/unknown codes?
            if i == cnt: break
            i += 1

    def geterr(self):

        """Return the last error message associated with this handle."""

        errmsg = _pcap.geterr(self.__pcap)
        return str(errmsg.decode("utf-8", "ignore")) if errmsg is not None else None

    def __iter__(self):

        _pcap_ex.setup(self.__pcap)
        return self

    def __next__(self):

        while True:
            # with nogil:
            n, hdr, pkt = _pcap_ex.next(self.__pcap)
            if n == 0:  # timeout
                continue
            elif n == 1:
                header = hdr[0]
                return (header.ts.tv_sec + (header.ts.tv_usec / 1000000.0),
                        ct.cast(pkt, ct.POINTER(ct.c_char * header.caplen))[0].raw)
            elif n == -1:
                raise KeyboardInterrupt()
            elif n == -2:
                raise StopIteration
            #else:  # AK: added
            #   ??? what about other/unknown codes?

    if sys.version_info[0] < 3:
        next = __next__


def ex_name(foo):

    cname = foo.encode("utf-8")        # AK: added
    cname = _pcap_ex.name(cname)
    return str(cname.decode("utf-8"))  # AK: added


def lookupdev():

    """Return the name of a network device suitable for sniffing."""

    ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
    name = _pcap_ex.lookupdev(ebuf)
    if name is None:
        raise OSError(str(ebuf.value.decode("utf-8", "ignore")))
    return str(name.decode("utf-8"))


def findalldevs():

    """Return a list of capture devices."""

    devs = ct.POINTER(_pcap.pcap_if_t)()
    ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
    status = _pcap.findalldevs(ct.byref(devs), ebuf)
    if status:
        raise OSError(str(ebuf.value.decode("utf-8", "ignore")))
    retval = []
    if not devs:
        return retval
    try:  # AK added
        dev = devs
        while dev:
            dev = dev[0]
            retval.append(str(dev.name.decode("utf-8")))
            dev = dev.next
    finally:
        _pcap.freealldevs(devs)
    return retval


def lookupnet(dev):

    """
    Return the address and the netmask of a given device
    as network-byteorder integers.
    """

    dev   = dev.encode("utf-8")  # AK: added
    netp  = ct.c_uint()
    maskp = ct.c_uint()
    ebuf  = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
    status = _pcap.lookupnet(dev, ct.byref(netp), ct.byref(maskp), ebuf)
    if status:
        raise OSError(str(ebuf.value.decode("utf-8", "ignore")))
    return struct.pack("I", netp.value), struct.pack("I", maskp.value)


@_pcap.pcap_handler
def _pcap_handler(arg, hdr, pkt): # with gil:

    ctx = ct.cast(arg, ct.POINTER(_pcap_handler_ctx))[0]
    try:
        header   = hdr[0]
        callback = ctx.callback
        args     = ctx.args
        callback(header.ts.tv_sec + (header.ts.tv_usec / 1000000.0),
                 ct.cast(pkt, ct.POINTER(ct.c_char * header.caplen))[0].raw,
                 *args)
    except:
        ctx.exc = sys.exc_info()


class _pcap_handler_ctx(ct.Structure):
    _fields_ = [
    ("callback", ct.py_object),
    ("args",     ct.py_object),
    ("exc",      ct.py_object),
]


# eof
