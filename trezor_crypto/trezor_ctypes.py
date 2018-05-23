# -*- coding: utf-8 -*-

import ctypes as ct
from .trezor_ctypes_gen import *

POINTER = POINTER_T
FE = bignum25519
MODM = bignum256modm
KEY_BUFF = ct.c_ubyte * 32
Ge25519 = ge25519
Ge25519_niels = ge25519_niels
Ge25519_pniels = ge25519_pniels
Ge25519_p1p1 = ge25519_p1p1
XmrRangeSig = xmr_range_sig_t
XmrAmount = xmr_amount


# bignum256modm = MODM
# bignum25519 = FE
#
# ge25519 = Ge25519
# ge25519_niels = Ge25519_niels
# ge25519_pniels = Ge25519_pniels
# ge25519_p1p1 = Ge25519_p1p1





