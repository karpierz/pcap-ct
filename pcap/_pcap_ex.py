# coding: utf-8

from __future__ import absolute_import

import os
import re
import tempfile
import socket
import select
import ctypes as ct

from annotate import annotate
from libpcap._platform import is_windows, is_osx, defined
from libpcap._platform import sockaddr_in
import libpcap as _pcap

if not is_windows:
    libc = ct.cdll.LoadLibrary("/lib64/libc.so.6")


@annotate(int, pcap=ct.POINTER(_pcap.pcap_t))
def immediate(pcap):

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


@annotate(bytes, bytes)
def name(name):

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

        try:  # AK: added
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


@annotate((bytes, None), ebuf=ct.c_char_p)
def lookupdev(ebuf):

    if is_windows:

        # Get all available devices.

        ret, devs = _findalldevs(ebuf)
        if ret == -1:
            return None

        name = None
        try:  # AK added
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


@annotate(int, pcap=ct.POINTER(_pcap.pcap_t))
def fileno(pcap):

    if is_windows:
        # XXX - how to handle savefiles?
        return _pcap.getevent(pcap)
    else:
        f = _pcap.file(pcap)  # FILE*
        if f:
            return libc.fileno(f)
        else:
            return _pcap.fileno(pcap)


@annotate(pcap=ct.POINTER(_pcap.pcap_t))
def setup(pcap):

    # XXX - hrr, this sux
    if is_windows:
        ct.windll.kernel32.SetConsoleCtrlHandler(__ctrl_handler, 1) #, TRUE)
    else:
        #if 0
        """
        fd = _pcap.fileno(pcap)
        n = fcntl(fd, F_GETFL, 0) | O_NONBLOCK  # ct.c_int
        fcntl(fd, F_SETFL, n);
        """
        #endif
        libc.signal(SIGINT, __signal_handler)


@annotate(int, pcap=ct.POINTER(_pcap.pcap_t), direction=int)
def setdirection(pcap, direction):

    try:
        _pcap.setdirection
    except AttributeError:
        return -2
    else:
        return _pcap.setdirection(pcap, direction)


@annotate(int, pcap=ct.POINTER(_pcap.pcap_t), ebuf=ct.c_char_p)
def getnonblock(pcap, ebuf):

    try:
        _pcap.getnonblock
    except AttributeError:
        return 0
    else:
        return _pcap.getnonblock(pcap, ebuf)


@annotate(pcap=ct.POINTER(_pcap.pcap_t), nonblock=int, ebuf=ct.c_char_p)
def setnonblock(pcap, nonblock, ebuf):

    try:
        _pcap.setnonblock
    except AttributeError:
        pass
    else:
        _pcap.setnonblock(pcap, nonblock, ebuf)


__hdr = _pcap.pkthdr()

@annotate(int, pcap=ct.POINTER(_pcap.pcap_t))
def next(pcap):

    # return codes: 1 = pkt, 0 = timeout, -1 = error, -2 = EOF

    global __got_signal

    if is_windows:

        hdr = ct.POINTER(_pcap.pkthdr)()
        pkt = ct.POINTER(ct.c_ubyte)()

        if __got_signal:
            __got_signal = False
            return -1, hdr, pkt

        ret = _pcap.next_ex(pcap, ct.byref(hdr), ct.byref(pkt))
        return ret, hdr, pkt

    else:

        global __hdr

        fd = _pcap.fileno(pcap)

        while True:

            hdr = ct.POINTER(_pcap.pkthdr)()
            pkt = ct.POINTER(ct.c_ubyte)()

            if __got_signal:
                __got_signal = False
                return -1, hdr, pkt

            pkt = ct.cast(_pcap.next(pcap, ct.byref(__hdr)), ct.POINTER(ct.c_ubyte))
            if pkt:
                break

            if _pcap.file(pcap):
                return -2, hdr, pkt

            try:
                rfds, wfds, efds = select.select([fd], [], [], 1.0)
            except:
                return -1, hdr, pkt
            if not rfds and not wfds and not efds:
                return 0, hdr, pkt  # timeout

        return 1, ct.pointer(__hdr), pkt


@annotate(int, snaplen=int, linktype=int,
          prog=ct.POINTER(_pcap.bpf_program),
          buffer=ct.c_char_p, optimize=int, mask=int)
def compile_nopcap(snaplen, linktype, prog, buffer, optimize, mask):

    try:
        _pcap.compile_nopcap
    except AttributeError:
        ret = -1

        try:
            f = tempfile.NamedTemporaryFile("wb", prefix=".pypcap", suffix=".pcap",
                                            delete=False)
        except:
            return ret

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
            if pcap is not None:
                try:
                    ret = _pcap.compile(pcap, prog, buffer, optimize, mask)
                finally:
                    _pcap.close(pcap)
        finally:
            os.unlink(f.name)

        return ret
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

    @annotate(tuple((int, ct.POINTER(_pcap.pcap_if_t))), ebuf=ct.c_char_p)
    def _findalldevs(ebuf):

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
        return 1 # TRUE

else:

    @ct.CFUNCTYPE(None, ct.c_int)
    def __signal_handler(sig):

        global __got_signal
        __got_signal = True


# eof
