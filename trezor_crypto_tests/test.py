#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest
import binascii
import logging

logger = logging.getLogger(__name__)
from trezor_crypto import trezor_cfunc
tcry = trezor_cfunc


class TcryTest(unittest.TestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(TcryTest, self).__init__(*args, **kwargs)

    def setUp(self):
        trezor_cfunc.open_lib()

    def test_ed_crypto(self):
        h_hex = b'8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94'
        h = binascii.unhexlify(h_hex)
        pt = tcry.ge25519_unpack_vartime_r(tcry.KEY_BUFF(*bytes(h)))
        packed = tcry.ge25519_pack_r(pt)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


