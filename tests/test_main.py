# Copyright (c) 2016 Adam Karpierz
# SPDX-License-Identifier: BSD-3-Clause

import unittest

import pcap

from .test import (
    test_pcap_iter,
    test_pcap_iter_ns,
    test_pcap_properties,
    test_pcap_errors,
    test_pcap_dispatch,
    test_pcap_dispatch_ns,
    test_pcap_dispatch_exception,
    test_pcap_readpkts,
    test_pcap_overwritten,
    test_pcap_loop_overwritten,
    test_unicode
)


class MainTestCase(unittest.TestCase):

    def setUp(self):
        pass

    def test_iter(self):
        test_pcap_iter()

    def test_iter_ns(self):
        test_pcap_iter_ns()

    def test_properties(self):
        test_pcap_properties()

    def test_errors(self):
        test_pcap_errors()

    def test_dispatch(self):
        test_pcap_dispatch()

    def test_dispatch_ns(self):
        test_pcap_dispatch_ns()

    def test_dispatch_exception(self):
        test_pcap_dispatch_exception()

    def test_readpkts(self):
        test_pcap_readpkts()

    def test_overwritten(self):
        test_pcap_overwritten()

    def test_loop_overwritten(self):
        test_pcap_loop_overwritten()

    def test_unicode_text(self):
        test_unicode()
