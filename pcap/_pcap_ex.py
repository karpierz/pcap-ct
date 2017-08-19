# coding: utf-8

from __future__ import absolute_import

import os
import tempfile
import socket
import select
import ctypes as ct

from libpcap._platform import is_windows, is_osx, defined
from libpcap._platform import CFUNC
import libpcap as _pcap

if not is_windows:
    libc = ct.cdll.LoadLibrary("/lib64/libc.so.6")


@CFUNC(ct.c_int, ct.POINTER(_pcap.pcap_t))
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


__pcap_name = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)

@CFUNC(ct.c_char_p, ct.c_char_p)
def name(name):

    name = ct.c_char_p(name)

    if is_windows:

        # XXX - translate from libdnet logical interface name to
        # WinPcap native interface name.

        global __pcap_name

        # XXX - according to the WinPcap FAQ, no loopback support???
        if not name.value.startswith(b"eth"):
            return name.value
        try:
            idx = int(name.value[3:])
            # sscanf(name+3, "%u", &idx) != 1 # !!! czy sscanf dziala dla np: 123xyz ???
        except ValueError:
            return name.value
        if idx < 0:
            return name.value

        pifs = ct.POINTER(_pcap.pcap_if_t)()
        ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
        if __findalldevs(ct.byref(pifs), ebuf) == -1:
            return name.value

        try:  # AK: added
            i   = 0
            pif = pifs
            while pif:
                pif = pif.contents
                if i == idx:
                    strncpy(__pcap_name, pif.name, ct.sizeof(__pcap_name) - 1) # !!!
                    __pcap_name[ct.sizeof(__pcap_name) - 1] = '\0'             # !!!
                    name = __pcap_name
                    break
                i  += 1
                pif = pif.next
        finally:
            _pcap.freealldevs(pifs)

        return name.value

    else:
        return name.value


@CFUNC(ct.c_char_p, ct.c_char_p)
def lookupdev(ebuf):

    if is_windows:

        # Get all available devices.

        pifs = ct.POINTER(_pcap.pcap_if_t)()
        if __findalldevs(ct.byref(pifs), ebuf) == -1:
            return None

        name = None
        try:  # AK added
            # Get first not 0.0.0.0 or 127.0.0.1 device
            pif  = pifs
            while pif:
                pif = pif.contents
                pa = pif.addresses
                while pa:
                    pa = pa.contents
                    addr_struct = pa.addr # (struct sockaddr_in *) pa.addr # !!!
                    addr = addr_struct.sin_addr.S_un.S_addr  # u_long      # !!!
                    if (addr_struct.sin_family == socket.AF_INET and
                        addr != 0 and        # 0.0.0.0
                        addr != 0x100007F):  # 127.0.0.1
                        name = pif.name
                        break
                    pa = pa.next
                pif = pif.next
        finally:
            _pcap.freealldevs(pifs)

        return name

    else:
        return _pcap.lookupdev(ebuf)


@CFUNC(ct.c_int, ct.POINTER(_pcap.pcap_t))
def fileno(pcap):

    if is_windows:
        # XXX - how to handle savefiles?
        return _pcap.getevent(pcap) # (ct.c_int) _pcap.getevent(pcap)
    else:
        f = _pcap.file(pcap)  # FILE*
        if f:
            return libc.fileno(f)
        else:
            return _pcap.fileno(pcap)


@CFUNC(None, ct.POINTER(_pcap.pcap_t))
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


@CFUNC(ct.c_int, ct.POINTER(_pcap.pcap_t), ct.c_int)
def setdirection(pcap, direction):

    try:
        _pcap.setdirection
    except AttributeError:
        return -2
    else:
        return _pcap.setdirection(pcap, direction)


@CFUNC(ct.c_int, ct.POINTER(_pcap.pcap_t), ct.c_char_p)
def getnonblock(pcap, ebuf):

    try:
        _pcap.getnonblock
    except AttributeError:
        return 0
    else:
        return _pcap.getnonblock(pcap, ebuf)


@CFUNC(None, ct.POINTER(_pcap.pcap_t), ct.c_int, ct.c_char_p)
def setnonblock(pcap, nonblock, ebuf):

    try:
        _pcap.setnonblock
    except AttributeError:
        pass
    else:
        _pcap.setnonblock(pcap, nonblock, ebuf)


__hdr = _pcap.pkthdr()
__pkt = ct.POINTER(ct.c_ubyte)()

@CFUNC(ct.c_int,
       ct.POINTER(_pcap.pcap_t),
       ct.POINTER(ct.POINTER(_pcap.pkthdr)),
       ct.POINTER(ct.POINTER(ct.c_ubyte)))
def next(pcap, hdr, pkt):

    # return codes: 1 = pkt, 0 = timeout, -1 = error, -2 = EOF

    global __got_signal

    if is_windows:

        if __got_signal:
            __got_signal = False
            return -1

        return _pcap.next_ex(pcap, hdr, pkt)

    else:

        global __hdr, __pkt

        fd = _pcap.fileno(pcap)

        while True:

            if __got_signal:
                __got_signal = False
                return -1

            __pkt = ct.cast(_pcap.next(pcap, ct.byref(__hdr)), ct.POINTER(ct.c_ubyte))
            if __pkt:
                break

            if _pcap.file(pcap):
                return -2

            try:
                rfds, wfds, efds = select.select([fd], [], [], 1.0)
            except:
                return -1
            if not rfds and not wfds and not efds:
                return 0  # timeout

        hdr.contents = ct.pointer(__hdr)
        pkt.contents = __pkt

        return 1


@CFUNC(ct.c_int,
       ct.c_int,
       ct.c_int,
       ct.POINTER(_pcap.bpf_program),
       ct.c_char_p,
       ct.c_int,
       ct.c_uint)
def compile_nopcap(snaplen, dlt, fp, buffer, optimize, netmask):

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
                hdr.linktype      = dlt
                f.fwrite(ct.byref(hdr), ct.sizeof(hdr), 1) # !!!

            ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
            pcap = _pcap.open_offline(f.name, ebuf)
            if pcap is not None:
                try:
                    ret = _pcap.compile(pcap, fp, buffer, optimize, netmask)
                finally:
                    _pcap.close(pcap)
        finally:
            os.unlink(f.name)

        return ret
    else:
        if defined("__NetBSD__"):
            # We love consistent interfaces
            ebuf = ct.create_string_buffer(_pcap.PCAP_ERRBUF_SIZE)
            return _pcap.compile_nopcap(snaplen, dlt, fp, buffer, optimize, netmask, ebuf)
        else:
            return _pcap.compile_nopcap(snaplen, dlt, fp, buffer, optimize, netmask)


__got_signal = False

if is_windows:

    import ctypes.wintypes

    @CFUNC(ct.c_int, ct.POINTER(ct.POINTER(_pcap.pcap_if_t)), ct.c_char_p)
    def __findalldevs(dst, ebuf):

        # XXX - set device list in libdnet order.

        pifs = ct.POINTER(_pcap.pcap_if_t)()
        ret = _pcap.findalldevs(ct.byref(pifs), ebuf)
        if ret == -1:
            return ret

        # XXX - flip script like a dyslexic actor
        prev, pif = None, pifs
        while pif:
            next = pif.contents.next
            pif.contents.next = prev
            prev, pif = pif, next
        dst.contents = prev

        return ret

    @ct.WINFUNCTYPE(ct.wintypes.BOOL, ct.wintypes.DWORD)
    def __ctrl_handler(sig):

        global __got_signal
        __got_signal = True
        return 1 # TRUE

else:

    @CFUNC(None, ct.c_int)
    def __signal_handler(sig):

        global __got_signal
        __got_signal = True


# eof
