# -*- coding: utf-8 -*-

import ctypes as ct
from .trezor_ctypes_gen import *

POINTER = ct.POINTER
FE = bignum25519
MODM = bignum256modm
KEY_BUFF = ct.c_ubyte * 32
Ge25519 = ge25519
Ge25519_niels = ge25519_niels
Ge25519_pniels = ge25519_pniels
Ge25519_p1p1 = ge25519_p1p1

