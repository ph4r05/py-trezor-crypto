# -*- coding: utf-8 -*-

import ctypes as ct
from .trezor_cfunc_gen import *


def random_buffer_r(sz):
    buff = (ct.c_uint8 * sz)()
    cl().random_buffer(ct.byref(buff), sz)
    return bytes(buff)


def get256_modm_r(a):
    r = ct.c_uint64()
    res = cl().get256_modm(ct.byref(r), a)
    if not res:
        raise ValueError('Get256_modm failed')
    return r.value


def expand256_modm(r, buff):
    cl().expand256_modm(r, buff, len(buff))
    return r


def expand256_modm_r(buff):
    m = tt.MODM()
    cl().expand256_modm(m, bytes(buff), len(buff))
    return m


def ge25519_unpack_vartime_r(buff):
    pt = tt.Ge25519()
    # buff = tt.KEY_BUFF(*buff)
    r = cl().ge25519_unpack_vartime(ct.byref(pt), buff)
    if r != 1:
        raise ValueError('Point decoding error')
    return pt


def xmr_fast_hash_r(a):
    r = tt.KEY_BUFF()
    cl().xmr_fast_hash(r, bytes(a), len(a))
    return bytes(r)


def xmr_hasher_update(h, buff):
    cl().xmr_hasher_update(ct.byref(h), bytes(buff), len(buff))


def xmr_hash_to_scalar(r, a):
    return cl().xmr_hash_to_scalar(r, bytes(a), len(a))


def xmr_hash_to_scalar_r(a):
    r = tt.MODM()
    cl().xmr_hash_to_scalar(r, bytes(a), len(a))
    return r


def xmr_hash_to_ec(r, a):
    return cl().xmr_hash_to_ec(ct.byref(r), bytes(a), len(a))


def xmr_hash_to_ec_r(a):
    r = tt.Ge25519()
    cl().xmr_hash_to_ec(ct.byref(r), bytes(a), len(a))
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



