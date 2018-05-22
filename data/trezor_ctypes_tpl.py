#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05

import os
import ctypes as ct
from trezor_crypto import trezor_ctypes as tt
from trezor_crypto import mod_base


# Loaded library instance
CLIB = None


def open_lib(lib_path=None, try_env=False, no_init=False):
    """
    Opens the library
    :param lib_path:
    :param try_env:
    :param no_init:
    :return:
    """
    global CLIB
    ext_fpath = lib_path

    if ext_fpath is None:
        ext_base = 'tcry_ctype'
        mods, basedir = mod_base.get_ext_outputs()
        ext_name = '%s%s' % (ext_base, mod_base.get_mod_suffix())
        extensions = ['.so', '.dylib', '.dll', '.pyd']
        ext_guesses = ['%s%s' % (ext_base, x) for x in extensions]

        if ext_name in mods:
            ext_fpath = os.path.join(basedir, ext_name)
        else:
            for g in ext_guesses:
                if g in mods:
                    ext_fpath = os.path.join(basedir, g)

    if ext_fpath is None and try_env:
        ext_fpath = os.getenv('LIBTREZOR_CRYPTO_PATH', None)

    if ext_fpath is None or not os.path.exists(ext_fpath):
        raise FileNotFoundError('Trezor-Crypto lib not found')

    CLIB = ct.cdll.LoadLibrary(ext_fpath)
    if not no_init:
        setup_lib(CLIB)
        init_lib()

    return CLIB


def cl():
    """
    Returns CLIB
    :return:
    """
    return CLIB


def init_lib():
    """
    Initializes Trezor crypto library
    :return:
    """
    res = cl().random_init()
    if res < 0:
        raise ValueError('Library initialization error: %s' % res)
    return res


def setup_lib(CLIB):
    """
    Setup the CLIB - define fncs
    :param CLIB:
    :return:
    """
    # {{ SETUP_LIB }}


#
# Wrappers
#


# {{ WRAPPERS }}


