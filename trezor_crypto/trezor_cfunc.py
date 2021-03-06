# -*- coding: utf-8 -*-

import ctypes as ct
from .trezor_ctypes import *
from .trezor_cfunc_gen import *


def random_buffer_r(sz):
    buff = (ct.c_uint8 * sz)()
    cl().random_buffer(buff, sz)
    return bytes(buff)


def init256_modm(r, a):
    cl().set256_modm(r, ct.c_uint64(a))
    return r


def init256_modm_r(a):
    r = tt.MODM()
    cl().set256_modm(r, ct.c_uint64(a))
    return r


def get256_modm_r(a):
    r = ct.c_uint64()
    res = cl().get256_modm(ct.byref(r), a)
    if not res:
        raise ValueError('Get256_modm failed')
    return r.value


def expand256_modm(r, buff, ln=None):
    cl().expand256_modm(r, buff, len(buff) if ln is None else ln)
    return r


def expand256_modm_r(buff, ln=None):
    m = tt.MODM()
    cl().expand256_modm(m, buff, len(buff) if ln is None else ln)
    return m


def curve25519_clone(a):
    r = tt.Ge25519()
    cl().curve25519_copy(r, a)
    return r


def new_ge25519():
    return tt.Ge25519()


def ge25519_unpack_vartime_r(buff):
    pt = tt.Ge25519()
    # buff = tt.KEY_BUFF(*buff)
    r = cl().ge25519_unpack_vartime(ct.byref(pt), buff)
    if r != 1:
        raise ValueError('Point decoding error')
    return pt


def ge25519_unpack_vartime(pt, buff):
    r = cl().ge25519_unpack_vartime(ct.byref(pt), buff)
    if r != 1:
        raise ValueError('Point decoding error')
    return pt


def xmr_fast_hash_r(a, ln=None):
    r = tt.KEY_BUFF()
    cl().xmr_fast_hash(r, a, len(a) if ln is None else ln)
    return bytes(r)


def xmr_hasher_update(h, buff, ln=None):
    cl().xmr_hasher_update(ct.byref(h), buff, len(buff) if ln is None else ln)


def xmr_hash_to_scalar(r, a, ln=None):
    return cl().xmr_hash_to_scalar(r, a, len(a) if ln is None else ln)


def xmr_hash_to_scalar_r(a, ln=None):
    r = tt.MODM()
    cl().xmr_hash_to_scalar(r, a, len(a) if ln is None else ln)
    return r


def xmr_hash_to_ec(r, a, ln=None):
    return cl().xmr_hash_to_ec(ct.byref(r), a, len(a) if ln is None else ln)


def xmr_hash_to_ec_r(a, ln=None):
    r = tt.Ge25519()
    cl().xmr_hash_to_ec(ct.byref(r), a, len(a) if ln is None else ln)
    return r


def gen_range_proof(amount, last_mask):
    """
    Trezor crypto range proof
    :param amount:
    :param last_mask:
    :return:
    """
    rsig = tt.XmrRangeSig()
    C = tt.Ge25519()
    mask = tt.MODM()
    last_mask_ptr = ct.byref(last_mask) if last_mask else None

    cl().xmr_gen_range_sig(ct.byref(rsig), ct.byref(C), mask, amount, last_mask_ptr)

    return C, mask, rsig



