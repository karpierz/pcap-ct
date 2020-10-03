# Copyright (c) 2016-2020, Adam Karpierz
# Licensed under the BSD license
# https://opensource.org/licenses/BSD-3-Clause

from typing import Optional, Tuple
import os
import re
import tempfile
import socket
import select
import ctypes as ct

from libpcap._platform import is_windows, is_osx, defined
from libpcap._platform import sockaddr_in
import libpcap as _pcap

if not is_windows:
    libc = ct.cdll.LoadLibrary("/lib64/libc.so.6")


def immediate(pcap: ct.POINTER(_pcap.pcap_t)) -> int:
    if is_windows:
        return _pcap.setmintocopy(pcap, 1)
    elif defined("BIOCIMMEDIATE"):
        # !!! BIOCIMMEDIATE ???
        import fcntl
        n = ct.c_int(1)
        return fcntl.ioctl(_pcap.fileno(pcap), BIOCIMMEDIATE, ct.byref(n))
    elif is_osx:
        # XXX On OSX Yosemite (10.10.3) BIOCIMMEDIATE is not defined)
        # !!! _IOW ???
        import fcntl
        n = ct.c_int(1)
        return fcntl.ioctl(_pcap.fileno(pcap), _IOW('B', 112, ct.c_uint), ct.byref(n))
    else:
        return 0


def name(name: bytes) -> bytes:
    if is_windows:

        # XXX - translate from libdnet logical interface name to
        # WinPcap native interface name.

        # XXX - according to the WinPcap FAQ, no loopback support???

        m = re.match(br"eth([-+]?\d+)", name)
        if not m:
            return name
        idx = int(m.group(1))
        if idx < 0:
            return name

        ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
        ret, devs = _findalldevs(ebuf)
        if ret == -1:
            return name

        try:  # <AK>: added
            i   = 0
            dev = devs
            while dev:
                dev = dev[0]
                if i == idx:
                    return dev.name
                i += 1
                dev = dev.next
        finally:
            _pcap.freealldevs(devs)

        return name
    else:
        return name


def lookupdev(ebuf: ct.c_char_p) -> Optional[bytes]:
    if is_windows:
        # Get all available devices.
        ret, devs = _findalldevs(ebuf)
        if ret == -1:
            return None

        name = None
        try:  # <AK> added
            # Get first not 0.0.0.0 or 127.0.0.1 device
            dev = devs
            while dev:
                dev = dev[0]
                pad = dev.addresses
                while pad:
                    pad = pad[0]
                    addr_struct = ct.cast(pad.addr, ct.POINTER(sockaddr_in))[0]
                    addr = addr_struct.sin_addr.s_addr
                   #addr = addr_struct.sin_addr.S_un.S_addr  # u_long # !!!
                    if (addr_struct.sin_family == socket.AF_INET and
                        addr != 0 and        # 0.0.0.0
                        addr != 0x100007F):  # 127.0.0.1
                        name = dev.name
                        break # !!! Ma znajdowac ostatnie (jak teraz/orginalnie) czy pierwsze ???
                    pad = pad.next
                dev = dev.next
        finally:
            _pcap.freealldevs(devs)

        return name
    else:
        return _pcap.lookupdev(ebuf)


def fileno(pcap: ct.POINTER(_pcap.pcap_t)) -> int:
    if is_windows:
        # XXX - how to handle savefiles?
        return _pcap.getevent(pcap)
    else:
        f = _pcap.file(pcap)  # FILE*
        if f:
            return libc.fileno(f)
        else:
            return _pcap.fileno(pcap)


def setup(pcap: ct.POINTER(_pcap.pcap_t)):
    # XXX - hrr, this sux
    if is_windows:
        ct.windll.kernel32.SetConsoleCtrlHandler(__ctrl_handler, 1) #, TRUE)
    else:
        if 0:
            import fcntl
            fd = _pcap.fileno(pcap)
            n = fcntl.fcntl(fd, F_GETFL, 0) | os.O_NONBLOCK
            fcntl.fcntl(fd, F_SETFL, n)
        libc.signal(SIGINT, __signal_handler)


"""/*
1.2.3: PCAP_API int pcap_next_ex(pcap_t*, struct pcap_pkthdr**, const u_char**);
def next_ex(pcap: ct.POINTER(_pcap.pcap_t), struct pcap_pkthdr** hdr, u_char** pkt) -> int:

        struct timeval tv = { 1, 0 };
        int fd, n;

            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            n = select(fd + 1, &rfds, NULL, NULL, &tv);
            if n <= 0:
                return n
*/
"""
def next_ex(pcap: ct.POINTER(_pcap.pcap_t),
            hdr: ct.POINTER(ct.POINTER(_pcap.pkthdr)),
            pkt: ct.POINTER(ct.POINTER(ct.c_ubyte))) -> int:
    # return codes: 1 = pkt, 0 = timeout, -1 = error, -2 = EOF

    global __got_signal

    if is_windows:
        if __got_signal:
            __got_signal = False
            return -1  # error

        return _pcap.next_ex(pcap, hdr, pkt)
    else:
        fd = _pcap.fileno(pcap)

        while True:
            if __got_signal:
                __got_signal = False
                return -1  # error

            pkt[0] = ct.cast(_pcap.next(pcap, hdr[0]), ct.POINTER(ct.c_ubyte))
            if pkt[0]:
                break

            if _pcap.file(pcap):
                return -2  # EOF

            try:
                rfds, wfds, efds = select.select([fd], [], [], 1.0)
            except:
                return -1  # error
            if not rfds and not wfds and not efds:
                return 0  # timeout

        return 1  # pkt (OK)


def compile_nopcap(snaplen: int, linktype: int, prog: ct.POINTER(_pcap.bpf_program),
                   buffer: ct.c_char_p, optimize: int, mask: int) -> int:
    try:
        _pcap.compile_nopcap
    except AttributeError:
        try:
            f = tempfile.NamedTemporaryFile("wb", prefix=".pypcap", suffix=".pcap",
                                            delete=False)
        except:
            return -1

        try:
            with f:
                hdr = _pcap.file_header()
                hdr.magic         = 0xA1B2C3D4
                hdr.version_major = _pcap.PCAP_VERSION_MAJOR
                hdr.version_minor = _pcap.PCAP_VERSION_MINOR
                hdr.thiszone      = 0
                hdr.snaplen       = snaplen
                hdr.sigfigs       = 0
                hdr.linktype      = linktype
                f.write(ct.cast(ct.pointer(hdr),
                                ct.POINTER(ct.c_char * ct.sizeof(hdr)))[0].raw)

            ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
            pcap = _pcap.open_offline(f.name, ebuf)
            if not pcap:
                return -1

            try:
                return _pcap.compile(pcap, prog, buffer, optimize, mask)
            finally:
                _pcap.close(pcap)
        finally:
            os.unlink(f.name)
    else:
        if defined("__NetBSD__"):
            # We love consistent interfaces
            ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
            return _pcap.compile_nopcap(snaplen, linktype, prog, buffer, optimize, mask, ebuf)
        else:
            return _pcap.compile_nopcap(snaplen, linktype, prog, buffer, optimize, mask)


__got_signal = False

if is_windows:

    import ctypes.wintypes

    def _findalldevs(ebuf: ct.c_char_p) -> Tuple[int, ct.POINTER(_pcap.pcap_if_t)]:

        # XXX - set device list in libdnet order.
        devs = ct.POINTER(_pcap.pcap_if_t)()
        ret = _pcap.findalldevs(ct.byref(devs), ebuf)
        if ret == -1:
            return ret, devs

        # XXX - flip script like a dyslexic actor
        prev, dev = ct.POINTER(_pcap.pcap_if_t)(), devs
        while dev:
            devo = dev[0]
            next = type(devo.next)()
            ct.pointer(next)[0] = devo.next
            devo.next = prev
            prev, dev = dev, next

        return ret, prev

    @ct.WINFUNCTYPE(ct.wintypes.BOOL, ct.wintypes.DWORD)
    def __ctrl_handler(sig):
        global __got_signal
        __got_signal = True
        return 1  # TRUE

else:

    @ct.CFUNCTYPE(None, ct.c_int)
    def __signal_handler(sig):
        global __got_signal
        __got_signal = True
