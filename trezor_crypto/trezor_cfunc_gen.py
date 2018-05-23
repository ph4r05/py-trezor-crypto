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
    
    # uint32_t random32(void)
    CLIB.random32.argtypes = []
    CLIB.random32.restype = tt.uint32_t
    
    # void random_buffer(uint8_t *buf, size_t len)
    CLIB.random_buffer.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t]
    
    # uint32_t random_uniform(uint32_t n)
    CLIB.random_uniform.argtypes = [tt.uint32_t]
    CLIB.random_uniform.restype = tt.uint32_t
    
    # void random_permute(char *buf, size_t len)
    CLIB.random_permute.argtypes = [tt.POINTER(ct.c_byte), tt.size_t]
    
    # int random_init(void)
    CLIB.random_init.argtypes = []
    CLIB.random_init.restype = ct.c_int
    
    # void sha1_Transform(const uint32_t *state_in, const uint32_t *data, uint32_t *state_out)
    CLIB.sha1_Transform.argtypes = [tt.POINTER(tt.uint32_t), tt.POINTER(tt.uint32_t), tt.POINTER(tt.uint32_t)]
    
    # void sha1_Init(SHA1_CTX *)
    CLIB.sha1_Init.argtypes = [tt.POINTER(tt.SHA1_CTX)]
    
    # void sha1_Update(SHA1_CTX *, const uint8_t *, size_t)
    CLIB.sha1_Update.argtypes = [tt.POINTER(tt.SHA1_CTX), tt.POINTER(tt.uint8_t), tt.size_t]
    
    # void sha1_Final(SHA1_CTX *, uint8_t [20])
    CLIB.sha1_Final.argtypes = [tt.POINTER(tt.SHA1_CTX), tt.uint8_t * 20]
    
    # char *sha1_End(SHA1_CTX *, char [(20 * 2) + 1])
    CLIB.sha1_End.argtypes = [tt.POINTER(tt.SHA1_CTX), ct.c_byte * 41]
    CLIB.sha1_End.restype = tt.POINTER(ct.c_byte)
    
    # void sha1_Raw(const uint8_t *, size_t, uint8_t [20])
    CLIB.sha1_Raw.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.uint8_t * 20]
    
    # char *sha1_Data(const uint8_t *, size_t, char [(20 * 2) + 1])
    CLIB.sha1_Data.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, ct.c_byte * 41]
    CLIB.sha1_Data.restype = tt.POINTER(ct.c_byte)
    
    # void sha256_Transform(const uint32_t *state_in, const uint32_t *data, uint32_t *state_out)
    CLIB.sha256_Transform.argtypes = [tt.POINTER(tt.uint32_t), tt.POINTER(tt.uint32_t), tt.POINTER(tt.uint32_t)]
    
    # void sha256_Init(SHA256_CTX *)
    CLIB.sha256_Init.argtypes = [tt.POINTER(tt.SHA256_CTX)]
    
    # void sha256_Update(SHA256_CTX *, const uint8_t *, size_t)
    CLIB.sha256_Update.argtypes = [tt.POINTER(tt.SHA256_CTX), tt.POINTER(tt.uint8_t), tt.size_t]
    
    # void sha256_Final(SHA256_CTX *, uint8_t [32])
    CLIB.sha256_Final.argtypes = [tt.POINTER(tt.SHA256_CTX), tt.uint8_t * 32]
    
    # char *sha256_End(SHA256_CTX *, char [(32 * 2) + 1])
    CLIB.sha256_End.argtypes = [tt.POINTER(tt.SHA256_CTX), ct.c_byte * 65]
    CLIB.sha256_End.restype = tt.POINTER(ct.c_byte)
    
    # void sha256_Raw(const uint8_t *, size_t, uint8_t [32])
    CLIB.sha256_Raw.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.uint8_t * 32]
    
    # char *sha256_Data(const uint8_t *, size_t, char [(32 * 2) + 1])
    CLIB.sha256_Data.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, ct.c_byte * 65]
    CLIB.sha256_Data.restype = tt.POINTER(ct.c_byte)
    
    # void sha512_Transform(const uint64_t *state_in, const uint64_t *data, uint64_t *state_out)
    CLIB.sha512_Transform.argtypes = [tt.POINTER(tt.uint64_t), tt.POINTER(tt.uint64_t), tt.POINTER(tt.uint64_t)]
    
    # void sha512_Init(SHA512_CTX *)
    CLIB.sha512_Init.argtypes = [tt.POINTER(tt.SHA512_CTX)]
    
    # void sha512_Update(SHA512_CTX *, const uint8_t *, size_t)
    CLIB.sha512_Update.argtypes = [tt.POINTER(tt.SHA512_CTX), tt.POINTER(tt.uint8_t), tt.size_t]
    
    # void sha512_Final(SHA512_CTX *, uint8_t [64])
    CLIB.sha512_Final.argtypes = [tt.POINTER(tt.SHA512_CTX), tt.uint8_t * 64]
    
    # char *sha512_End(SHA512_CTX *, char [(64 * 2) + 1])
    CLIB.sha512_End.argtypes = [tt.POINTER(tt.SHA512_CTX), ct.c_byte * 129]
    CLIB.sha512_End.restype = tt.POINTER(ct.c_byte)
    
    # void sha512_Raw(const uint8_t *, size_t, uint8_t [64])
    CLIB.sha512_Raw.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.uint8_t * 64]
    
    # char *sha512_Data(const uint8_t *, size_t, char [(64 * 2) + 1])
    CLIB.sha512_Data.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, ct.c_byte * 129]
    CLIB.sha512_Data.restype = tt.POINTER(ct.c_byte)
    
    # void sha3_224_Init(SHA3_CTX *ctx)
    CLIB.sha3_224_Init.argtypes = [tt.POINTER(tt.SHA3_CTX)]
    
    # void sha3_256_Init(SHA3_CTX *ctx)
    CLIB.sha3_256_Init.argtypes = [tt.POINTER(tt.SHA3_CTX)]
    
    # void sha3_384_Init(SHA3_CTX *ctx)
    CLIB.sha3_384_Init.argtypes = [tt.POINTER(tt.SHA3_CTX)]
    
    # void sha3_512_Init(SHA3_CTX *ctx)
    CLIB.sha3_512_Init.argtypes = [tt.POINTER(tt.SHA3_CTX)]
    
    # void sha3_Update(SHA3_CTX *ctx, const char *msg, size_t size)
    CLIB.sha3_Update.argtypes = [tt.POINTER(tt.SHA3_CTX), tt.POINTER(ct.c_ubyte), tt.size_t]
    
    # void sha3_Final(SHA3_CTX *ctx, char *result)
    CLIB.sha3_Final.argtypes = [tt.POINTER(tt.SHA3_CTX), tt.POINTER(ct.c_ubyte)]
    
    # void keccak_Final(SHA3_CTX *ctx, char *result)
    CLIB.keccak_Final.argtypes = [tt.POINTER(tt.SHA3_CTX), tt.POINTER(ct.c_ubyte)]
    
    # void keccak_256(const char *data, size_t len, char *digest)
    CLIB.keccak_256.argtypes = [tt.POINTER(ct.c_ubyte), tt.size_t, tt.POINTER(ct.c_ubyte)]
    
    # void keccak_512(const char *data, size_t len, char *digest)
    CLIB.keccak_512.argtypes = [tt.POINTER(ct.c_ubyte), tt.size_t, tt.POINTER(ct.c_ubyte)]
    
    # void sha3_256(const char *data, size_t len, char *digest)
    CLIB.sha3_256.argtypes = [tt.POINTER(ct.c_ubyte), tt.size_t, tt.POINTER(ct.c_ubyte)]
    
    # void sha3_512(const char *data, size_t len, char *digest)
    CLIB.sha3_512.argtypes = [tt.POINTER(ct.c_ubyte), tt.size_t, tt.POINTER(ct.c_ubyte)]
    
    # void blake256_Init(BLAKE256_CTX *)
    CLIB.blake256_Init.argtypes = [tt.POINTER(tt.BLAKE256_CTX)]
    
    # void blake256_Update(BLAKE256_CTX *, const uint8_t *, size_t)
    CLIB.blake256_Update.argtypes = [tt.POINTER(tt.BLAKE256_CTX), tt.POINTER(tt.uint8_t), tt.size_t]
    
    # void blake256_Final(BLAKE256_CTX *, uint8_t *)
    CLIB.blake256_Final.argtypes = [tt.POINTER(tt.BLAKE256_CTX), tt.POINTER(tt.uint8_t)]
    
    # void blake256(const uint8_t *, size_t, uint8_t *)
    CLIB.blake256.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.POINTER(tt.uint8_t)]
    
    # void groestl512_Init(void *cc)
    CLIB.groestl512_Init.argtypes = [ct.c_void_p]
    
    # void groestl512_Update(void *cc, const void *data, size_t len)
    CLIB.groestl512_Update.argtypes = [ct.c_void_p, ct.c_void_p, tt.size_t]
    
    # void groestl512_Final(void *cc, void *dst)
    CLIB.groestl512_Final.argtypes = [ct.c_void_p, ct.c_void_p]
    
    # void groestl512_DoubleTrunc(void *cc, void *dst)
    CLIB.groestl512_DoubleTrunc.argtypes = [ct.c_void_p, ct.c_void_p]
    
    # void hasher_Init(Hasher *hasher, HasherType type)
    CLIB.hasher_Init.argtypes = [tt.POINTER(tt.Hasher), tt.HasherType]
    
    # void hasher_Reset(Hasher *hasher)
    CLIB.hasher_Reset.argtypes = [tt.POINTER(tt.Hasher)]
    
    # void hasher_Update(Hasher *hasher, const uint8_t *data, size_t length)
    CLIB.hasher_Update.argtypes = [tt.POINTER(tt.Hasher), tt.POINTER(tt.uint8_t), tt.size_t]
    
    # void hasher_Final(Hasher *hasher, uint8_t hash[32])
    CLIB.hasher_Final.argtypes = [tt.POINTER(tt.Hasher), tt.uint8_t * 32]
    
    # void hasher_Raw(HasherType type, const uint8_t *data, size_t length, uint8_t hash[32])
    CLIB.hasher_Raw.argtypes = [tt.HasherType, tt.POINTER(tt.uint8_t), tt.size_t, tt.uint8_t * 32]
    
    # void hmac_sha256_Init(HMAC_SHA256_CTX *hctx, const uint8_t *key, const uint32_t keylen)
    CLIB.hmac_sha256_Init.argtypes = [tt.POINTER(tt.HMAC_SHA256_CTX), tt.POINTER(tt.uint8_t), tt.uint32_t]
    
    # void hmac_sha256_Update(HMAC_SHA256_CTX *hctx, const uint8_t *msg, const uint32_t msglen)
    CLIB.hmac_sha256_Update.argtypes = [tt.POINTER(tt.HMAC_SHA256_CTX), tt.POINTER(tt.uint8_t), tt.uint32_t]
    
    # void hmac_sha256_Final(HMAC_SHA256_CTX *hctx, uint8_t *hmac)
    CLIB.hmac_sha256_Final.argtypes = [tt.POINTER(tt.HMAC_SHA256_CTX), tt.POINTER(tt.uint8_t)]
    
    # void hmac_sha256(const uint8_t *key, const uint32_t keylen, const uint8_t *msg, const uint32_t msglen, uint8_t *hmac)
    CLIB.hmac_sha256.argtypes = [tt.POINTER(tt.uint8_t), tt.uint32_t, tt.POINTER(tt.uint8_t), tt.uint32_t, tt.POINTER(tt.uint8_t)]
    
    # void hmac_sha256_prepare(const uint8_t *key, const uint32_t keylen, uint32_t *opad_digest, uint32_t *ipad_digest)
    CLIB.hmac_sha256_prepare.argtypes = [tt.POINTER(tt.uint8_t), tt.uint32_t, tt.POINTER(tt.uint32_t), tt.POINTER(tt.uint32_t)]
    
    # void hmac_sha512_Init(HMAC_SHA512_CTX *hctx, const uint8_t *key, const uint32_t keylen)
    CLIB.hmac_sha512_Init.argtypes = [tt.POINTER(tt.HMAC_SHA512_CTX), tt.POINTER(tt.uint8_t), tt.uint32_t]
    
    # void hmac_sha512_Update(HMAC_SHA512_CTX *hctx, const uint8_t *msg, const uint32_t msglen)
    CLIB.hmac_sha512_Update.argtypes = [tt.POINTER(tt.HMAC_SHA512_CTX), tt.POINTER(tt.uint8_t), tt.uint32_t]
    
    # void hmac_sha512_Final(HMAC_SHA512_CTX *hctx, uint8_t *hmac)
    CLIB.hmac_sha512_Final.argtypes = [tt.POINTER(tt.HMAC_SHA512_CTX), tt.POINTER(tt.uint8_t)]
    
    # void hmac_sha512(const uint8_t *key, const uint32_t keylen, const uint8_t *msg, const uint32_t msglen, uint8_t *hmac)
    CLIB.hmac_sha512.argtypes = [tt.POINTER(tt.uint8_t), tt.uint32_t, tt.POINTER(tt.uint8_t), tt.uint32_t, tt.POINTER(tt.uint8_t)]
    
    # void hmac_sha512_prepare(const uint8_t *key, const uint32_t keylen, uint64_t *opad_digest, uint64_t *ipad_digest)
    CLIB.hmac_sha512_prepare.argtypes = [tt.POINTER(tt.uint8_t), tt.uint32_t, tt.POINTER(tt.uint64_t), tt.POINTER(tt.uint64_t)]
    
    # void pbkdf2_hmac_sha256_Init(PBKDF2_HMAC_SHA256_CTX *pctx, const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen)
    CLIB.pbkdf2_hmac_sha256_Init.argtypes = [tt.POINTER(tt.PBKDF2_HMAC_SHA256_CTX), tt.POINTER(tt.uint8_t), ct.c_int, tt.POINTER(tt.uint8_t), ct.c_int]
    
    # void pbkdf2_hmac_sha256_Update(PBKDF2_HMAC_SHA256_CTX *pctx, uint32_t iterations)
    CLIB.pbkdf2_hmac_sha256_Update.argtypes = [tt.POINTER(tt.PBKDF2_HMAC_SHA256_CTX), tt.uint32_t]
    
    # void pbkdf2_hmac_sha256_Final(PBKDF2_HMAC_SHA256_CTX *pctx, uint8_t *key)
    CLIB.pbkdf2_hmac_sha256_Final.argtypes = [tt.POINTER(tt.PBKDF2_HMAC_SHA256_CTX), tt.POINTER(tt.uint8_t)]
    
    # void pbkdf2_hmac_sha256(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key)
    CLIB.pbkdf2_hmac_sha256.argtypes = [tt.POINTER(tt.uint8_t), ct.c_int, tt.POINTER(tt.uint8_t), ct.c_int, tt.uint32_t, tt.POINTER(tt.uint8_t)]
    
    # void pbkdf2_hmac_sha512_Init(PBKDF2_HMAC_SHA512_CTX *pctx, const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen)
    CLIB.pbkdf2_hmac_sha512_Init.argtypes = [tt.POINTER(tt.PBKDF2_HMAC_SHA512_CTX), tt.POINTER(tt.uint8_t), ct.c_int, tt.POINTER(tt.uint8_t), ct.c_int]
    
    # void pbkdf2_hmac_sha512_Update(PBKDF2_HMAC_SHA512_CTX *pctx, uint32_t iterations)
    CLIB.pbkdf2_hmac_sha512_Update.argtypes = [tt.POINTER(tt.PBKDF2_HMAC_SHA512_CTX), tt.uint32_t]
    
    # void pbkdf2_hmac_sha512_Final(PBKDF2_HMAC_SHA512_CTX *pctx, uint8_t *key)
    CLIB.pbkdf2_hmac_sha512_Final.argtypes = [tt.POINTER(tt.PBKDF2_HMAC_SHA512_CTX), tt.POINTER(tt.uint8_t)]
    
    # void pbkdf2_hmac_sha512(const uint8_t *pass, int passlen, const uint8_t *salt, int saltlen, uint32_t iterations, uint8_t *key)
    CLIB.pbkdf2_hmac_sha512.argtypes = [tt.POINTER(tt.uint8_t), ct.c_int, tt.POINTER(tt.uint8_t), ct.c_int, tt.uint32_t, tt.POINTER(tt.uint8_t)]
    
    # uint32_t read_be(const uint8_t *data)
    CLIB.read_be.argtypes = [tt.POINTER(tt.uint8_t)]
    CLIB.read_be.restype = tt.uint32_t
    
    # void write_be(uint8_t *data, uint32_t x)
    CLIB.write_be.argtypes = [tt.POINTER(tt.uint8_t), tt.uint32_t]
    
    # uint32_t read_le(const uint8_t *data)
    CLIB.read_le.argtypes = [tt.POINTER(tt.uint8_t)]
    CLIB.read_le.restype = tt.uint32_t
    
    # void write_le(uint8_t *data, uint32_t x)
    CLIB.write_le.argtypes = [tt.POINTER(tt.uint8_t), tt.uint32_t]
    
    # void bn_read_be(const uint8_t *in_number, bignum256 *out_number)
    CLIB.bn_read_be.argtypes = [tt.POINTER(tt.uint8_t), tt.POINTER(tt.bignum256)]
    
    # void bn_write_be(const bignum256 *in_number, uint8_t *out_number)
    CLIB.bn_write_be.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.uint8_t)]
    
    # void bn_read_le(const uint8_t *in_number, bignum256 *out_number)
    CLIB.bn_read_le.argtypes = [tt.POINTER(tt.uint8_t), tt.POINTER(tt.bignum256)]
    
    # void bn_write_le(const bignum256 *in_number, uint8_t *out_number)
    CLIB.bn_write_le.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.uint8_t)]
    
    # void bn_read_uint32(uint32_t in_number, bignum256 *out_number)
    CLIB.bn_read_uint32.argtypes = [tt.uint32_t, tt.POINTER(tt.bignum256)]
    
    # void bn_read_uint64(uint64_t in_number, bignum256 *out_number)
    CLIB.bn_read_uint64.argtypes = [tt.uint64_t, tt.POINTER(tt.bignum256)]
    
    # int bn_bitcount(const bignum256 *a)
    CLIB.bn_bitcount.argtypes = [tt.POINTER(tt.bignum256)]
    CLIB.bn_bitcount.restype = ct.c_int
    
    # int bn_digitcount(const bignum256 *a)
    CLIB.bn_digitcount.argtypes = [tt.POINTER(tt.bignum256)]
    CLIB.bn_digitcount.restype = ct.c_uint
    
    # void bn_zero(bignum256 *a)
    CLIB.bn_zero.argtypes = [tt.POINTER(tt.bignum256)]
    
    # int bn_is_zero(const bignum256 *a)
    CLIB.bn_is_zero.argtypes = [tt.POINTER(tt.bignum256)]
    CLIB.bn_is_zero.restype = ct.c_int
    
    # void bn_one(bignum256 *a)
    CLIB.bn_one.argtypes = [tt.POINTER(tt.bignum256)]
    
    # int bn_is_less(const bignum256 *a, const bignum256 *b)
    CLIB.bn_is_less.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    CLIB.bn_is_less.restype = ct.c_int
    
    # int bn_is_equal(const bignum256 *a, const bignum256 *b)
    CLIB.bn_is_equal.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    CLIB.bn_is_equal.restype = ct.c_int
    
    # void bn_cmov(bignum256 *res, int cond, const bignum256 *truecase, const bignum256 *falsecase)
    CLIB.bn_cmov.argtypes = [tt.POINTER(tt.bignum256), ct.c_int, tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_lshift(bignum256 *a)
    CLIB.bn_lshift.argtypes = [tt.POINTER(tt.bignum256)]
    
    # void bn_rshift(bignum256 *a)
    CLIB.bn_rshift.argtypes = [tt.POINTER(tt.bignum256)]
    
    # void bn_setbit(bignum256 *a, uint8_t bit)
    CLIB.bn_setbit.argtypes = [tt.POINTER(tt.bignum256), tt.uint8_t]
    
    # void bn_clearbit(bignum256 *a, uint8_t bit)
    CLIB.bn_clearbit.argtypes = [tt.POINTER(tt.bignum256), tt.uint8_t]
    
    # uint32_t bn_testbit(bignum256 *a, uint8_t bit)
    CLIB.bn_testbit.argtypes = [tt.POINTER(tt.bignum256), tt.uint8_t]
    CLIB.bn_testbit.restype = tt.uint32_t
    
    # void bn_xor(bignum256 *a, const bignum256 *b, const bignum256 *c)
    CLIB.bn_xor.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_mult_half(bignum256 *x, const bignum256 *prime)
    CLIB.bn_mult_half.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_mult_k(bignum256 *x, uint8_t k, const bignum256 *prime)
    CLIB.bn_mult_k.argtypes = [tt.POINTER(tt.bignum256), tt.uint8_t, tt.POINTER(tt.bignum256)]
    
    # void bn_mod(bignum256 *x, const bignum256 *prime)
    CLIB.bn_mod.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_multiply(const bignum256 *k, bignum256 *x, const bignum256 *prime)
    CLIB.bn_multiply.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_fast_mod(bignum256 *x, const bignum256 *prime)
    CLIB.bn_fast_mod.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_sqrt(bignum256 *x, const bignum256 *prime)
    CLIB.bn_sqrt.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_inverse(bignum256 *x, const bignum256 *prime)
    CLIB.bn_inverse.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_normalize(bignum256 *a)
    CLIB.bn_normalize.argtypes = [tt.POINTER(tt.bignum256)]
    
    # void bn_add(bignum256 *a, const bignum256 *b)
    CLIB.bn_add.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_addmod(bignum256 *a, const bignum256 *b, const bignum256 *prime)
    CLIB.bn_addmod.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_addi(bignum256 *a, uint32_t b)
    CLIB.bn_addi.argtypes = [tt.POINTER(tt.bignum256), tt.uint32_t]
    
    # void bn_subi(bignum256 *a, uint32_t b, const bignum256 *prime)
    CLIB.bn_subi.argtypes = [tt.POINTER(tt.bignum256), tt.uint32_t, tt.POINTER(tt.bignum256)]
    
    # void bn_subtractmod(const bignum256 *a, const bignum256 *b, bignum256 *res, const bignum256 *prime)
    CLIB.bn_subtractmod.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_subtract(const bignum256 *a, const bignum256 *b, bignum256 *res)
    CLIB.bn_subtract.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256), tt.POINTER(tt.bignum256)]
    
    # void bn_divmod58(bignum256 *a, uint32_t *r)
    CLIB.bn_divmod58.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.uint32_t)]
    
    # void bn_divmod1000(bignum256 *a, uint32_t *r)
    CLIB.bn_divmod1000.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(tt.uint32_t)]
    
    # size_t bn_format(const bignum256 *amnt, const char *prefix, const char *suffix, int decimals, int exponent, bool trailing, char *out, size_t outlen)
    CLIB.bn_format.argtypes = [tt.POINTER(tt.bignum256), tt.POINTER(ct.c_byte), tt.POINTER(ct.c_byte), ct.c_uint, ct.c_int, ct.c_bool, tt.POINTER(ct.c_byte), tt.size_t]
    CLIB.bn_format.restype = tt.size_t
    
    # char *base32_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen, const char *alphabet)
    CLIB.base32_encode.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.POINTER(ct.c_byte), tt.size_t, tt.POINTER(ct.c_byte)]
    CLIB.base32_encode.restype = tt.POINTER(ct.c_byte)
    
    # void base32_encode_unsafe(const uint8_t *in, size_t inlen, uint8_t *out)
    CLIB.base32_encode_unsafe.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.POINTER(tt.uint8_t)]
    
    # uint8_t *base32_decode(const char *in, size_t inlen, uint8_t *out, size_t outlen, const char *alphabet)
    CLIB.base32_decode.argtypes = [tt.POINTER(ct.c_byte), tt.size_t, tt.POINTER(tt.uint8_t), tt.size_t, tt.POINTER(ct.c_byte)]
    CLIB.base32_decode.restype = tt.POINTER(tt.uint8_t)
    
    # bool base32_decode_unsafe(const uint8_t *in, size_t inlen, uint8_t *out, const char *alphabet)
    CLIB.base32_decode_unsafe.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.POINTER(tt.uint8_t), tt.POINTER(ct.c_byte)]
    CLIB.base32_decode_unsafe.restype = ct.c_bool
    
    # size_t base32_encoded_length(size_t inlen)
    CLIB.base32_encoded_length.argtypes = [tt.size_t]
    CLIB.base32_encoded_length.restype = tt.size_t
    
    # size_t base32_decoded_length(size_t inlen)
    CLIB.base32_decoded_length.argtypes = [tt.size_t]
    CLIB.base32_decoded_length.restype = tt.size_t
    
    # int base58_encode_check(const uint8_t *data, int len, HasherType hasher_type, char *str, int strsize)
    CLIB.base58_encode_check.argtypes = [tt.POINTER(tt.uint8_t), ct.c_int, tt.HasherType, tt.POINTER(ct.c_byte), ct.c_int]
    CLIB.base58_encode_check.restype = ct.c_int
    
    # int base58_decode_check(const char *str, HasherType hasher_type, uint8_t *data, int datalen)
    CLIB.base58_decode_check.argtypes = [tt.POINTER(ct.c_byte), tt.HasherType, tt.POINTER(tt.uint8_t), ct.c_int]
    CLIB.base58_decode_check.restype = ct.c_int
    
    # bool b58tobin(void *bin, size_t *binszp, const char *b58)
    CLIB.b58tobin.argtypes = [ct.c_void_p, tt.POINTER(tt.size_t), tt.POINTER(ct.c_byte)]
    CLIB.b58tobin.restype = ct.c_bool
    
    # int b58check(const void *bin, size_t binsz, HasherType hasher_type, const char *base58str)
    CLIB.b58check.argtypes = [ct.c_void_p, tt.size_t, tt.HasherType, tt.POINTER(ct.c_byte)]
    CLIB.b58check.restype = ct.c_int
    
    # bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz)
    CLIB.b58enc.argtypes = [tt.POINTER(ct.c_byte), tt.POINTER(tt.size_t), ct.c_void_p, tt.size_t]
    CLIB.b58enc.restype = ct.c_bool
    
    # int xmr_base58_addr_encode_check(uint64_t tag, const uint8_t *data, size_t binsz, char *b58, size_t b58sz)
    CLIB.xmr_base58_addr_encode_check.argtypes = [tt.uint64_t, tt.POINTER(tt.uint8_t), tt.size_t, tt.POINTER(ct.c_byte), tt.size_t]
    CLIB.xmr_base58_addr_encode_check.restype = ct.c_int
    
    # int xmr_base58_addr_decode_check(const char *addr, size_t sz, uint64_t *tag, void *data, size_t datalen)
    CLIB.xmr_base58_addr_decode_check.argtypes = [tt.POINTER(ct.c_byte), tt.size_t, tt.POINTER(tt.uint64_t), ct.c_void_p, tt.size_t]
    CLIB.xmr_base58_addr_decode_check.restype = ct.c_int
    
    # bool xmr_base58_encode(char *b58, size_t *b58sz, const void *data, size_t binsz)
    CLIB.xmr_base58_encode.argtypes = [tt.POINTER(ct.c_byte), tt.POINTER(tt.size_t), ct.c_void_p, tt.size_t]
    CLIB.xmr_base58_encode.restype = ct.c_bool
    
    # bool xmr_base58_decode(const char *b58, size_t b58sz, void *data, size_t *binsz)
    CLIB.xmr_base58_decode.argtypes = [tt.POINTER(ct.c_byte), tt.size_t, ct.c_void_p, tt.POINTER(tt.size_t)]
    CLIB.xmr_base58_decode.restype = ct.c_bool
    
    # void curve25519_copy(bignum25519 out, const bignum25519 in)
    CLIB.curve25519_copy.argtypes = [tt.bignum25519, tt.bignum25519]
    
    # void curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b)
    CLIB.curve25519_add.argtypes = [tt.bignum25519, tt.bignum25519, tt.bignum25519]
    
    # void curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b)
    CLIB.curve25519_add_after_basic.argtypes = [tt.bignum25519, tt.bignum25519, tt.bignum25519]
    
    # void curve25519_add_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b)
    CLIB.curve25519_add_reduce.argtypes = [tt.bignum25519, tt.bignum25519, tt.bignum25519]
    
    # void curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b)
    CLIB.curve25519_sub.argtypes = [tt.bignum25519, tt.bignum25519, tt.bignum25519]
    
    # void curve25519_scalar_product(bignum25519 out, const bignum25519 in, const uint32_t scalar)
    CLIB.curve25519_scalar_product.argtypes = [tt.bignum25519, tt.bignum25519, tt.uint32_t]
    
    # void curve25519_sub_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b)
    CLIB.curve25519_sub_after_basic.argtypes = [tt.bignum25519, tt.bignum25519, tt.bignum25519]
    
    # void curve25519_sub_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b)
    CLIB.curve25519_sub_reduce.argtypes = [tt.bignum25519, tt.bignum25519, tt.bignum25519]
    
    # void curve25519_neg(bignum25519 out, const bignum25519 a)
    CLIB.curve25519_neg.argtypes = [tt.bignum25519, tt.bignum25519]
    
    # void curve25519_mul(bignum25519 out, const bignum25519 a, const bignum25519 b)
    CLIB.curve25519_mul.argtypes = [tt.bignum25519, tt.bignum25519, tt.bignum25519]
    
    # void curve25519_square(bignum25519 out, const bignum25519 in)
    CLIB.curve25519_square.argtypes = [tt.bignum25519, tt.bignum25519]
    
    # void curve25519_square_times(bignum25519 out, const bignum25519 in, int count)
    CLIB.curve25519_square_times.argtypes = [tt.bignum25519, tt.bignum25519, ct.c_int]
    
    # void curve25519_expand(bignum25519 out, const char in[32])
    CLIB.curve25519_expand.argtypes = [tt.bignum25519, ct.c_ubyte * 32]
    
    # void curve25519_contract(char out[32], const bignum25519 in)
    CLIB.curve25519_contract.argtypes = [ct.c_ubyte * 32, tt.bignum25519]
    
    # void curve25519_swap_conditional(bignum25519 a, bignum25519 b, uint32_t iswap)
    CLIB.curve25519_swap_conditional.argtypes = [tt.bignum25519, tt.bignum25519, tt.uint32_t]
    
    # void curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b)
    CLIB.curve25519_pow_two5mtwo0_two250mtwo0.argtypes = [tt.bignum25519]
    
    # void curve25519_recip(bignum25519 out, const bignum25519 z)
    CLIB.curve25519_recip.argtypes = [tt.bignum25519, tt.bignum25519]
    
    # void curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z)
    CLIB.curve25519_pow_two252m3.argtypes = [tt.bignum25519, tt.bignum25519]
    
    # void reduce256_modm(bignum256modm r)
    CLIB.reduce256_modm.argtypes = [tt.bignum256modm]
    
    # void barrett_reduce256_modm(bignum256modm r, const bignum256modm q1, const bignum256modm r1)
    CLIB.barrett_reduce256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm, tt.bignum256modm]
    
    # void add256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y)
    CLIB.add256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm, tt.bignum256modm]
    
    # void neg256_modm(bignum256modm r, const bignum256modm x)
    CLIB.neg256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm]
    
    # void sub256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y)
    CLIB.sub256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm, tt.bignum256modm]
    
    # void mul256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y)
    CLIB.mul256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm, tt.bignum256modm]
    
    # void expand256_modm(bignum256modm out, const char *in, size_t len)
    CLIB.expand256_modm.argtypes = [tt.bignum256modm, tt.POINTER(ct.c_ubyte), tt.size_t]
    
    # void expand_raw256_modm(bignum256modm out, const char in[32])
    CLIB.expand_raw256_modm.argtypes = [tt.bignum256modm, ct.c_ubyte * 32]
    
    # void contract256_modm(char out[32], const bignum256modm in)
    CLIB.contract256_modm.argtypes = [ct.c_ubyte * 32, tt.bignum256modm]
    
    # void contract256_window4_modm(char r[64], const bignum256modm in)
    CLIB.contract256_window4_modm.argtypes = [ct.c_byte * 64, tt.bignum256modm]
    
    # void contract256_slidingwindow_modm(char r[256], const bignum256modm s, int windowsize)
    CLIB.contract256_slidingwindow_modm.argtypes = [ct.c_byte * 256, tt.bignum256modm, ct.c_int]
    
    # int ed25519_verify(const char *x, const char *y, size_t len)
    CLIB.ed25519_verify.argtypes = [tt.POINTER(ct.c_ubyte), tt.POINTER(ct.c_ubyte), tt.size_t]
    CLIB.ed25519_verify.restype = ct.c_int
    
    # void ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p)
    CLIB.ge25519_p1p1_to_partial.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519_p1p1)]
    
    # void ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p)
    CLIB.ge25519_p1p1_to_full.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519_p1p1)]
    
    # void ge25519_full_to_pniels(ge25519_pniels *p, const ge25519 *r)
    CLIB.ge25519_full_to_pniels.argtypes = [tt.POINTER(tt.ge25519_pniels), tt.POINTER(tt.ge25519)]
    
    # void ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p)
    CLIB.ge25519_double_p1p1.argtypes = [tt.POINTER(tt.ge25519_p1p1), tt.POINTER(tt.ge25519)]
    
    # void ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q, char signbit)
    CLIB.ge25519_nielsadd2_p1p1.argtypes = [tt.POINTER(tt.ge25519_p1p1), tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519_niels), ct.c_ubyte]
    
    # void ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q, char signbit)
    CLIB.ge25519_pnielsadd_p1p1.argtypes = [tt.POINTER(tt.ge25519_p1p1), tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519_pniels), ct.c_ubyte]
    
    # void ge25519_double_partial(ge25519 *r, const ge25519 *p)
    CLIB.ge25519_double_partial.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519)]
    
    # void ge25519_double(ge25519 *r, const ge25519 *p)
    CLIB.ge25519_double.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519)]
    
    # void ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q)
    CLIB.ge25519_nielsadd2.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519_niels)]
    
    # void ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q)
    CLIB.ge25519_pnielsadd.argtypes = [tt.POINTER(tt.ge25519_pniels), tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519_pniels)]
    
    # void ge25519_pack(char r[32], const ge25519 *p)
    CLIB.ge25519_pack.argtypes = [ct.c_ubyte * 32, tt.POINTER(tt.ge25519)]
    
    # int ge25519_unpack_negative_vartime(ge25519 *r, const char p[32])
    CLIB.ge25519_unpack_negative_vartime.argtypes = [tt.POINTER(tt.ge25519), ct.c_ubyte * 32]
    CLIB.ge25519_unpack_negative_vartime.restype = ct.c_int
    
    # void ge25519_set_neutral(ge25519 *r)
    CLIB.ge25519_set_neutral.argtypes = [tt.POINTER(tt.ge25519)]
    
    # void ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2)
    CLIB.ge25519_double_scalarmult_vartime.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), tt.bignum256modm, tt.bignum256modm]
    
    # void ge25519_double_scalarmult_vartime2(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const ge25519 *p2, const bignum256modm s2)
    CLIB.ge25519_double_scalarmult_vartime2.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), tt.bignum256modm, tt.POINTER(tt.ge25519), tt.bignum256modm]
    
    # void ge25519_scalarmult(ge25519 *r, const ge25519 *p1, const bignum256modm s1)
    CLIB.ge25519_scalarmult.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), tt.bignum256modm]
    
    # void set256_modm(bignum256modm r, uint64_t v)
    CLIB.set256_modm.argtypes = [tt.bignum256modm, tt.uint64_t]
    
    # int get256_modm(uint64_t *v, const bignum256modm r)
    CLIB.get256_modm.argtypes = [tt.POINTER(tt.uint64_t), tt.bignum256modm]
    CLIB.get256_modm.restype = ct.c_int
    
    # int eq256_modm(const bignum256modm x, const bignum256modm y)
    CLIB.eq256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm]
    CLIB.eq256_modm.restype = ct.c_int
    
    # int cmp256_modm(const bignum256modm x, const bignum256modm y)
    CLIB.cmp256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm]
    CLIB.cmp256_modm.restype = ct.c_int
    
    # int iszero256_modm(const bignum256modm x)
    CLIB.iszero256_modm.argtypes = [tt.bignum256modm]
    CLIB.iszero256_modm.restype = ct.c_int
    
    # void copy256_modm(bignum256modm r, const bignum256modm x)
    CLIB.copy256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm]
    
    # int check256_modm(const bignum256modm x)
    CLIB.check256_modm.argtypes = [tt.bignum256modm]
    CLIB.check256_modm.restype = ct.c_int
    
    # void mulsub256_modm(bignum256modm r, const bignum256modm a, const bignum256modm b, const bignum256modm c)
    CLIB.mulsub256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm, tt.bignum256modm, tt.bignum256modm]
    
    # void muladd256_modm(bignum256modm r, const bignum256modm a, const bignum256modm b, const bignum256modm c)
    CLIB.muladd256_modm.argtypes = [tt.bignum256modm, tt.bignum256modm, tt.bignum256modm, tt.bignum256modm]
    
    # void curve25519_set(bignum25519 r, uint32_t x)
    CLIB.curve25519_set.argtypes = [tt.bignum25519, tt.uint32_t]
    
    # void curve25519_set_d(bignum25519 r)
    CLIB.curve25519_set_d.argtypes = [tt.bignum25519]
    
    # void curve25519_set_2d(bignum25519 r)
    CLIB.curve25519_set_2d.argtypes = [tt.bignum25519]
    
    # void curve25519_set_sqrtneg1(bignum25519 r)
    CLIB.curve25519_set_sqrtneg1.argtypes = [tt.bignum25519]
    
    # int curve25519_isnegative(const bignum25519 f)
    CLIB.curve25519_isnegative.argtypes = [tt.bignum25519]
    CLIB.curve25519_isnegative.restype = ct.c_int
    
    # int curve25519_isnonzero(const bignum25519 f)
    CLIB.curve25519_isnonzero.argtypes = [tt.bignum25519]
    CLIB.curve25519_isnonzero.restype = ct.c_int
    
    # void curve25519_reduce(bignum25519 r, const bignum25519 in)
    CLIB.curve25519_reduce.argtypes = [tt.bignum25519, tt.bignum25519]
    
    # void curve25519_expand_reduce(bignum25519 out, const char in[32])
    CLIB.curve25519_expand_reduce.argtypes = [tt.bignum25519, ct.c_ubyte * 32]
    
    # int ge25519_check(const ge25519 *r)
    CLIB.ge25519_check.argtypes = [tt.POINTER(tt.ge25519)]
    CLIB.ge25519_check.restype = ct.c_int
    
    # int ge25519_fromfe_check(const ge25519 *r)
    CLIB.ge25519_fromfe_check.argtypes = [tt.POINTER(tt.ge25519)]
    CLIB.ge25519_fromfe_check.restype = ct.c_int
    
    # int ge25519_eq(const ge25519 *a, const ge25519 *b)
    CLIB.ge25519_eq.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519)]
    CLIB.ge25519_eq.restype = ct.c_int
    
    # void ge25519_copy(ge25519 *dst, const ge25519 *src)
    CLIB.ge25519_copy.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519)]
    
    # void ge25519_set_base(ge25519 *r)
    CLIB.ge25519_set_base.argtypes = [tt.POINTER(tt.ge25519)]
    
    # void ge25519_mul8(ge25519 *r, const ge25519 *t)
    CLIB.ge25519_mul8.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519)]
    
    # void ge25519_neg_partial(ge25519 *r)
    CLIB.ge25519_neg_partial.argtypes = [tt.POINTER(tt.ge25519)]
    
    # void ge25519_neg_full(ge25519 *r)
    CLIB.ge25519_neg_full.argtypes = [tt.POINTER(tt.ge25519)]
    
    # void ge25519_reduce(ge25519 *r, const ge25519 *t)
    CLIB.ge25519_reduce.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519)]
    
    # void ge25519_norm(ge25519 *r, const ge25519 *t)
    CLIB.ge25519_norm.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519)]
    
    # void ge25519_add(ge25519 *r, const ge25519 *a, const ge25519 *b, char signbit)
    CLIB.ge25519_add.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), ct.c_ubyte]
    
    # void ge25519_fromfe_frombytes_vartime(ge25519 *r, const char *s)
    CLIB.ge25519_fromfe_frombytes_vartime.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(ct.c_ubyte)]
    
    # int ge25519_unpack_vartime(ge25519 *r, const char *s)
    CLIB.ge25519_unpack_vartime.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(ct.c_ubyte)]
    CLIB.ge25519_unpack_vartime.restype = ct.c_int
    
    # void ge25519_scalarmult_base_wrapper(ge25519 *r, const bignum256modm s)
    CLIB.ge25519_scalarmult_base_wrapper.argtypes = [tt.POINTER(tt.ge25519), tt.bignum256modm]
    
    # void ge25519_scalarmult_wrapper(ge25519 *r, const ge25519 *P, const bignum256modm a)
    CLIB.ge25519_scalarmult_wrapper.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), tt.bignum256modm]
    
    # int xmr_size_varint(uint64_t num)
    CLIB.xmr_size_varint.argtypes = [tt.uint64_t]
    CLIB.xmr_size_varint.restype = ct.c_int
    
    # int xmr_write_varint(uint8_t *buff, size_t buff_size, uint64_t num)
    CLIB.xmr_write_varint.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.uint64_t]
    CLIB.xmr_write_varint.restype = ct.c_int
    
    # int xmr_read_varint(uint8_t *buff, size_t buff_size, uint64_t *val)
    CLIB.xmr_read_varint.argtypes = [tt.POINTER(tt.uint8_t), tt.size_t, tt.POINTER(tt.uint64_t)]
    CLIB.xmr_read_varint.restype = ct.c_int
    
    # void ge25519_set_xmr_h(ge25519 *r)
    CLIB.ge25519_set_xmr_h.argtypes = [tt.POINTER(tt.ge25519)]
    
    # void xmr_random_scalar(bignum256modm m)
    CLIB.xmr_random_scalar.argtypes = [tt.bignum256modm]
    
    # void xmr_fast_hash(uint8_t *hash, const void *data, size_t length)
    CLIB.xmr_fast_hash.argtypes = [tt.POINTER(tt.uint8_t), ct.c_void_p, tt.size_t]
    
    # void xmr_hasher_init(Hasher *hasher)
    CLIB.xmr_hasher_init.argtypes = [tt.POINTER(tt.Hasher)]
    
    # void xmr_hasher_update(Hasher *hasher, const void *data, size_t length)
    CLIB.xmr_hasher_update.argtypes = [tt.POINTER(tt.Hasher), ct.c_void_p, tt.size_t]
    
    # void xmr_hasher_final(Hasher *hasher, uint8_t *hash)
    CLIB.xmr_hasher_final.argtypes = [tt.POINTER(tt.Hasher), tt.POINTER(tt.uint8_t)]
    
    # void xmr_hasher_copy(Hasher *dst, const Hasher *src)
    CLIB.xmr_hasher_copy.argtypes = [tt.POINTER(tt.Hasher), tt.POINTER(tt.Hasher)]
    
    # void xmr_hash_to_scalar(bignum256modm r, const void *data, size_t length)
    CLIB.xmr_hash_to_scalar.argtypes = [tt.bignum256modm, ct.c_void_p, tt.size_t]
    
    # void xmr_hash_to_ec(ge25519 *P, const void *data, size_t length)
    CLIB.xmr_hash_to_ec.argtypes = [tt.POINTER(tt.ge25519), ct.c_void_p, tt.size_t]
    
    # void xmr_derivation_to_scalar(bignum256modm s, const ge25519 *p, uint32_t output_index)
    CLIB.xmr_derivation_to_scalar.argtypes = [tt.bignum256modm, tt.POINTER(tt.ge25519), tt.uint32_t]
    
    # void xmr_generate_key_derivation(ge25519 *r, const ge25519 *A, const bignum256modm b)
    CLIB.xmr_generate_key_derivation.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), tt.bignum256modm]
    
    # void xmr_derive_private_key(bignum256modm s, const ge25519 *deriv, uint32_t idx, const bignum256modm base)
    CLIB.xmr_derive_private_key.argtypes = [tt.bignum256modm, tt.POINTER(tt.ge25519), tt.uint32_t, tt.bignum256modm]
    
    # void xmr_derive_public_key(ge25519 *r, const ge25519 *deriv, uint32_t idx, const ge25519 *base)
    CLIB.xmr_derive_public_key.argtypes = [tt.POINTER(tt.ge25519), tt.POINTER(tt.ge25519), tt.uint32_t, tt.POINTER(tt.ge25519)]
    
    # void xmr_add_keys2(ge25519 *r, const bignum256modm a, const bignum256modm b, const ge25519 *B)
    CLIB.xmr_add_keys2.argtypes = [tt.POINTER(tt.ge25519), tt.bignum256modm, tt.bignum256modm, tt.POINTER(tt.ge25519)]
    
    # void xmr_add_keys2_vartime(ge25519 *r, const bignum256modm a, const bignum256modm b, const ge25519 *B)
    CLIB.xmr_add_keys2_vartime.argtypes = [tt.POINTER(tt.ge25519), tt.bignum256modm, tt.bignum256modm, tt.POINTER(tt.ge25519)]
    
    # void xmr_add_keys3(ge25519 *r, const bignum256modm a, const ge25519 *A, const bignum256modm b, const ge25519 *B)
    CLIB.xmr_add_keys3.argtypes = [tt.POINTER(tt.ge25519), tt.bignum256modm, tt.POINTER(tt.ge25519), tt.bignum256modm, tt.POINTER(tt.ge25519)]
    
    # void xmr_add_keys3_vartime(ge25519 *r, const bignum256modm a, const ge25519 *A, const bignum256modm b, const ge25519 *B)
    CLIB.xmr_add_keys3_vartime.argtypes = [tt.POINTER(tt.ge25519), tt.bignum256modm, tt.POINTER(tt.ge25519), tt.bignum256modm, tt.POINTER(tt.ge25519)]
    
    # void xmr_get_subaddress_secret_key(bignum256modm r, uint32_t major, uint32_t minor, const bignum256modm m)
    CLIB.xmr_get_subaddress_secret_key.argtypes = [tt.bignum256modm, tt.uint32_t, tt.uint32_t, tt.bignum256modm]
    
    # void xmr_gen_c(ge25519 *r, const bignum256modm a, uint64_t amount)
    CLIB.xmr_gen_c.argtypes = [tt.POINTER(tt.ge25519), tt.bignum256modm, tt.uint64_t]
    
    # void xmr_gen_range_sig(xmr_range_sig_t *sig, ge25519 *C, bignum256modm mask, xmr_amount amount, bignum256modm *last_mask)
    CLIB.xmr_gen_range_sig.argtypes = [tt.POINTER(tt.xmr_range_sig_t), tt.POINTER(tt.ge25519), tt.bignum256modm, tt.xmr_amount, tt.POINTER(tt.bignum256modm)]


#
# Wrappers
#


def random32(): 
    return int(CLIB.random32())


def random_buffer(buf, len): 
    CLIB.random_buffer(buf, len)


def random_buffer_r(len): 
    buf = (tt.uint8_t)()
    CLIB.random_buffer(buf, len)
    return bytes(buf)


def random_uniform(n): 
    return int(CLIB.random_uniform(n))


def random_permute(buf, len): 
    CLIB.random_permute(buf, len)


def random_permute_r(len): 
    buf = (ct.c_byte)()
    CLIB.random_permute(buf, len)
    return bytes(buf)


def random_init(): 
    return int(CLIB.random_init())


def sha1_Transform(state_in, data, state_out): 
    CLIB.sha1_Transform(ct.byref(state_in), ct.byref(data), ct.byref(state_out))


def sha1_Transform_r(state_in, data): 
    state_out = (tt.uint32_t)()
    CLIB.sha1_Transform(ct.byref(state_in), ct.byref(data), ct.byref(state_out))
    return state_out


def sha1_Init(r): 
    CLIB.sha1_Init(ct.byref(r))


def sha1_Init_r(): 
    r = (tt.SHA1_CTX)()
    CLIB.sha1_Init(ct.byref(r))
    return r


def sha1_Update(r, a, b): 
    CLIB.sha1_Update(ct.byref(r), a, b)


def sha1_Update_r(a, b): 
    r = (tt.SHA1_CTX)()
    CLIB.sha1_Update(ct.byref(r), a, b)
    return r


def sha1_Final(r, a): 
    CLIB.sha1_Final(ct.byref(r), a)


def sha1_Final_r(): 
    r = (tt.SHA1_CTX)()
    a = (tt.uint8_t * 20)()
    CLIB.sha1_Final(ct.byref(r), a)
    return r, bytes(a)


def sha1_End(r, a): 
    return bytes(CLIB.sha1_End(ct.byref(r), a))


def sha1_End_r(): 
    r = (tt.SHA1_CTX)()
    a = (ct.c_byte * 41)()
    _res = CLIB.sha1_End(ct.byref(r), a)
    return bytes(_res), r, bytes(a)


def sha1_Raw(r, a, b): 
    CLIB.sha1_Raw(r, a, b)


def sha1_Raw_r(r, a): 
    b = (tt.uint8_t * 20)()
    CLIB.sha1_Raw(r, a, b)
    return bytes(b)


def sha1_Data(r, a, b): 
    return bytes(CLIB.sha1_Data(r, a, b))


def sha1_Data_r(r, a): 
    b = (ct.c_byte * 41)()
    _res = CLIB.sha1_Data(r, a, b)
    return bytes(_res), bytes(b)


def sha256_Transform(state_in, data, state_out): 
    CLIB.sha256_Transform(ct.byref(state_in), ct.byref(data), ct.byref(state_out))


def sha256_Transform_r(state_in, data): 
    state_out = (tt.uint32_t)()
    CLIB.sha256_Transform(ct.byref(state_in), ct.byref(data), ct.byref(state_out))
    return state_out


def sha256_Init(r): 
    CLIB.sha256_Init(ct.byref(r))


def sha256_Init_r(): 
    r = (tt.SHA256_CTX)()
    CLIB.sha256_Init(ct.byref(r))
    return r


def sha256_Update(r, a, b): 
    CLIB.sha256_Update(ct.byref(r), a, b)


def sha256_Update_r(a, b): 
    r = (tt.SHA256_CTX)()
    CLIB.sha256_Update(ct.byref(r), a, b)
    return r


def sha256_Final(r, a): 
    CLIB.sha256_Final(ct.byref(r), a)


def sha256_Final_r(): 
    r = (tt.SHA256_CTX)()
    a = (tt.uint8_t * 32)()
    CLIB.sha256_Final(ct.byref(r), a)
    return r, bytes(a)


def sha256_End(r, a): 
    return bytes(CLIB.sha256_End(ct.byref(r), a))


def sha256_End_r(): 
    r = (tt.SHA256_CTX)()
    a = (ct.c_byte * 65)()
    _res = CLIB.sha256_End(ct.byref(r), a)
    return bytes(_res), r, bytes(a)


def sha256_Raw(r, a, b): 
    CLIB.sha256_Raw(r, a, b)


def sha256_Raw_r(r, a): 
    b = (tt.uint8_t * 32)()
    CLIB.sha256_Raw(r, a, b)
    return bytes(b)


def sha256_Data(r, a, b): 
    return bytes(CLIB.sha256_Data(r, a, b))


def sha256_Data_r(r, a): 
    b = (ct.c_byte * 65)()
    _res = CLIB.sha256_Data(r, a, b)
    return bytes(_res), bytes(b)


def sha512_Transform(state_in, data, state_out): 
    CLIB.sha512_Transform(ct.byref(state_in), ct.byref(data), ct.byref(state_out))


def sha512_Transform_r(state_in, data): 
    state_out = (tt.uint64_t)()
    CLIB.sha512_Transform(ct.byref(state_in), ct.byref(data), ct.byref(state_out))
    return state_out


def sha512_Init(r): 
    CLIB.sha512_Init(ct.byref(r))


def sha512_Init_r(): 
    r = (tt.SHA512_CTX)()
    CLIB.sha512_Init(ct.byref(r))
    return r


def sha512_Update(r, a, b): 
    CLIB.sha512_Update(ct.byref(r), a, b)


def sha512_Update_r(a, b): 
    r = (tt.SHA512_CTX)()
    CLIB.sha512_Update(ct.byref(r), a, b)
    return r


def sha512_Final(r, a): 
    CLIB.sha512_Final(ct.byref(r), a)


def sha512_Final_r(): 
    r = (tt.SHA512_CTX)()
    a = (tt.uint8_t * 64)()
    CLIB.sha512_Final(ct.byref(r), a)
    return r, bytes(a)


def sha512_End(r, a): 
    return bytes(CLIB.sha512_End(ct.byref(r), a))


def sha512_End_r(): 
    r = (tt.SHA512_CTX)()
    a = (ct.c_byte * 129)()
    _res = CLIB.sha512_End(ct.byref(r), a)
    return bytes(_res), r, bytes(a)


def sha512_Raw(r, a, b): 
    CLIB.sha512_Raw(r, a, b)


def sha512_Raw_r(r, a): 
    b = (tt.uint8_t * 64)()
    CLIB.sha512_Raw(r, a, b)
    return bytes(b)


def sha512_Data(r, a, b): 
    return bytes(CLIB.sha512_Data(r, a, b))


def sha512_Data_r(r, a): 
    b = (ct.c_byte * 129)()
    _res = CLIB.sha512_Data(r, a, b)
    return bytes(_res), bytes(b)


def sha3_224_Init(ctx): 
    CLIB.sha3_224_Init(ct.byref(ctx))


def sha3_224_Init_r(): 
    ctx = (tt.SHA3_CTX)()
    CLIB.sha3_224_Init(ct.byref(ctx))
    return ctx


def sha3_256_Init(ctx): 
    CLIB.sha3_256_Init(ct.byref(ctx))


def sha3_256_Init_r(): 
    ctx = (tt.SHA3_CTX)()
    CLIB.sha3_256_Init(ct.byref(ctx))
    return ctx


def sha3_384_Init(ctx): 
    CLIB.sha3_384_Init(ct.byref(ctx))


def sha3_384_Init_r(): 
    ctx = (tt.SHA3_CTX)()
    CLIB.sha3_384_Init(ct.byref(ctx))
    return ctx


def sha3_512_Init(ctx): 
    CLIB.sha3_512_Init(ct.byref(ctx))


def sha3_512_Init_r(): 
    ctx = (tt.SHA3_CTX)()
    CLIB.sha3_512_Init(ct.byref(ctx))
    return ctx


def sha3_Update(ctx, msg, size): 
    CLIB.sha3_Update(ct.byref(ctx), msg, size)


def sha3_Update_r(msg, size): 
    ctx = (tt.SHA3_CTX)()
    CLIB.sha3_Update(ct.byref(ctx), msg, size)
    return ctx


def sha3_Final(ctx, result): 
    CLIB.sha3_Final(ct.byref(ctx), result)


def sha3_Final_r(): 
    ctx = (tt.SHA3_CTX)()
    result = (ct.c_ubyte)()
    CLIB.sha3_Final(ct.byref(ctx), result)
    return ctx, bytes(result)


def keccak_Final(ctx, result): 
    CLIB.keccak_Final(ct.byref(ctx), result)


def keccak_Final_r(): 
    ctx = (tt.SHA3_CTX)()
    result = (ct.c_ubyte)()
    CLIB.keccak_Final(ct.byref(ctx), result)
    return ctx, bytes(result)


def keccak_256(data, len, digest): 
    CLIB.keccak_256(data, len, digest)


def keccak_256_r(data, len): 
    digest = (ct.c_ubyte)()
    CLIB.keccak_256(data, len, digest)
    return bytes(digest)


def keccak_512(data, len, digest): 
    CLIB.keccak_512(data, len, digest)


def keccak_512_r(data, len): 
    digest = (ct.c_ubyte)()
    CLIB.keccak_512(data, len, digest)
    return bytes(digest)


def sha3_256(data, len, digest): 
    CLIB.sha3_256(data, len, digest)


def sha3_256_r(data, len): 
    digest = (ct.c_ubyte)()
    CLIB.sha3_256(data, len, digest)
    return bytes(digest)


def sha3_512(data, len, digest): 
    CLIB.sha3_512(data, len, digest)


def sha3_512_r(data, len): 
    digest = (ct.c_ubyte)()
    CLIB.sha3_512(data, len, digest)
    return bytes(digest)


def blake256_Init(r): 
    CLIB.blake256_Init(ct.byref(r))


def blake256_Init_r(): 
    r = (tt.BLAKE256_CTX)()
    CLIB.blake256_Init(ct.byref(r))
    return r


def blake256_Update(r, a, b): 
    CLIB.blake256_Update(ct.byref(r), a, b)


def blake256_Update_r(a, b): 
    r = (tt.BLAKE256_CTX)()
    CLIB.blake256_Update(ct.byref(r), a, b)
    return r


def blake256_Final(r, a): 
    CLIB.blake256_Final(ct.byref(r), a)


def blake256_Final_r(): 
    r = (tt.BLAKE256_CTX)()
    a = (tt.uint8_t)()
    CLIB.blake256_Final(ct.byref(r), a)
    return r, bytes(a)


def blake256(r, a, b): 
    CLIB.blake256(r, a, b)


def blake256_r(r, a): 
    b = (tt.uint8_t)()
    CLIB.blake256(r, a, b)
    return bytes(b)


def groestl512_Init(cc): 
    CLIB.groestl512_Init(ct.byref(cc))


def groestl512_Init_r(): 
    cc = (ct.c_void_p)()
    CLIB.groestl512_Init(ct.byref(cc))
    return cc


def groestl512_Update(cc, data, len): 
    CLIB.groestl512_Update(ct.byref(cc), ct.byref(data), len)


def groestl512_Update_r(data, len): 
    cc = (ct.c_void_p)()
    CLIB.groestl512_Update(ct.byref(cc), ct.byref(data), len)
    return cc


def groestl512_Final(cc, dst): 
    CLIB.groestl512_Final(ct.byref(cc), ct.byref(dst))


def groestl512_Final_r(): 
    cc = (ct.c_void_p)()
    dst = (ct.c_void_p)()
    CLIB.groestl512_Final(ct.byref(cc), ct.byref(dst))
    return cc, dst


def groestl512_DoubleTrunc(cc, dst): 
    CLIB.groestl512_DoubleTrunc(ct.byref(cc), ct.byref(dst))


def groestl512_DoubleTrunc_r(): 
    cc = (ct.c_void_p)()
    dst = (ct.c_void_p)()
    CLIB.groestl512_DoubleTrunc(ct.byref(cc), ct.byref(dst))
    return cc, dst


def hasher_Init(hasher, type): 
    CLIB.hasher_Init(ct.byref(hasher), type)


def hasher_Init_r(): 
    hasher = (tt.Hasher)()
    type = (tt.HasherType)()
    CLIB.hasher_Init(ct.byref(hasher), type)
    return hasher, type


def hasher_Reset(hasher): 
    CLIB.hasher_Reset(ct.byref(hasher))


def hasher_Reset_r(): 
    hasher = (tt.Hasher)()
    CLIB.hasher_Reset(ct.byref(hasher))
    return hasher


def hasher_Update(hasher, data, length): 
    CLIB.hasher_Update(ct.byref(hasher), data, length)


def hasher_Update_r(data, length): 
    hasher = (tt.Hasher)()
    CLIB.hasher_Update(ct.byref(hasher), data, length)
    return hasher


def hasher_Final(hasher, hash): 
    CLIB.hasher_Final(ct.byref(hasher), hash)


def hasher_Final_r(): 
    hasher = (tt.Hasher)()
    hash = (tt.uint8_t * 32)()
    CLIB.hasher_Final(ct.byref(hasher), hash)
    return hasher, bytes(hash)


def hasher_Raw(type, data, length, hash): 
    CLIB.hasher_Raw(type, data, length, hash)


def hasher_Raw_r(data, length, hash): 
    type = (tt.HasherType)()
    CLIB.hasher_Raw(type, data, length, hash)
    return type


def hmac_sha256_Init(hctx, key, keylen): 
    CLIB.hmac_sha256_Init(ct.byref(hctx), key, keylen)


def hmac_sha256_Init_r(key, keylen): 
    hctx = (tt.HMAC_SHA256_CTX)()
    CLIB.hmac_sha256_Init(ct.byref(hctx), key, keylen)
    return hctx


def hmac_sha256_Update(hctx, msg, msglen): 
    CLIB.hmac_sha256_Update(ct.byref(hctx), msg, msglen)


def hmac_sha256_Update_r(msg, msglen): 
    hctx = (tt.HMAC_SHA256_CTX)()
    CLIB.hmac_sha256_Update(ct.byref(hctx), msg, msglen)
    return hctx


def hmac_sha256_Final(hctx, hmac): 
    CLIB.hmac_sha256_Final(ct.byref(hctx), hmac)


def hmac_sha256_Final_r(): 
    hctx = (tt.HMAC_SHA256_CTX)()
    hmac = (tt.uint8_t)()
    CLIB.hmac_sha256_Final(ct.byref(hctx), hmac)
    return hctx, bytes(hmac)


def hmac_sha256(key, keylen, msg, msglen, hmac): 
    CLIB.hmac_sha256(key, keylen, msg, msglen, hmac)


def hmac_sha256_r(key, keylen, msg, msglen): 
    hmac = (tt.uint8_t)()
    CLIB.hmac_sha256(key, keylen, msg, msglen, hmac)
    return bytes(hmac)


def hmac_sha256_prepare(key, keylen, opad_digest, ipad_digest): 
    CLIB.hmac_sha256_prepare(key, keylen, ct.byref(opad_digest), ct.byref(ipad_digest))


def hmac_sha256_prepare_r(key, keylen): 
    opad_digest = (tt.uint32_t)()
    ipad_digest = (tt.uint32_t)()
    CLIB.hmac_sha256_prepare(key, keylen, ct.byref(opad_digest), ct.byref(ipad_digest))
    return bytes(opad_digest), int(ipad_digest)


def hmac_sha512_Init(hctx, key, keylen): 
    CLIB.hmac_sha512_Init(ct.byref(hctx), key, keylen)


def hmac_sha512_Init_r(key, keylen): 
    hctx = (tt.HMAC_SHA512_CTX)()
    CLIB.hmac_sha512_Init(ct.byref(hctx), key, keylen)
    return hctx


def hmac_sha512_Update(hctx, msg, msglen): 
    CLIB.hmac_sha512_Update(ct.byref(hctx), msg, msglen)


def hmac_sha512_Update_r(msg, msglen): 
    hctx = (tt.HMAC_SHA512_CTX)()
    CLIB.hmac_sha512_Update(ct.byref(hctx), msg, msglen)
    return hctx


def hmac_sha512_Final(hctx, hmac): 
    CLIB.hmac_sha512_Final(ct.byref(hctx), hmac)


def hmac_sha512_Final_r(): 
    hctx = (tt.HMAC_SHA512_CTX)()
    hmac = (tt.uint8_t)()
    CLIB.hmac_sha512_Final(ct.byref(hctx), hmac)
    return hctx, bytes(hmac)


def hmac_sha512(key, keylen, msg, msglen, hmac): 
    CLIB.hmac_sha512(key, keylen, msg, msglen, hmac)


def hmac_sha512_r(key, keylen, msg, msglen): 
    hmac = (tt.uint8_t)()
    CLIB.hmac_sha512(key, keylen, msg, msglen, hmac)
    return bytes(hmac)


def hmac_sha512_prepare(key, keylen, opad_digest, ipad_digest): 
    CLIB.hmac_sha512_prepare(key, keylen, ct.byref(opad_digest), ct.byref(ipad_digest))


def hmac_sha512_prepare_r(key, keylen): 
    opad_digest = (tt.uint64_t)()
    ipad_digest = (tt.uint64_t)()
    CLIB.hmac_sha512_prepare(key, keylen, ct.byref(opad_digest), ct.byref(ipad_digest))
    return bytes(opad_digest), int(ipad_digest)


def pbkdf2_hmac_sha256_Init(pctx, pass_, passlen, salt, saltlen): 
    CLIB.pbkdf2_hmac_sha256_Init(ct.byref(pctx), pass_, passlen, salt, saltlen)


def pbkdf2_hmac_sha256_Init_r(pass_, passlen, salt, saltlen): 
    pctx = (tt.PBKDF2_HMAC_SHA256_CTX)()
    CLIB.pbkdf2_hmac_sha256_Init(ct.byref(pctx), pass_, passlen, salt, saltlen)
    return pctx


def pbkdf2_hmac_sha256_Update(pctx, iterations): 
    CLIB.pbkdf2_hmac_sha256_Update(ct.byref(pctx), iterations)


def pbkdf2_hmac_sha256_Update_r(iterations): 
    pctx = (tt.PBKDF2_HMAC_SHA256_CTX)()
    CLIB.pbkdf2_hmac_sha256_Update(ct.byref(pctx), iterations)
    return pctx


def pbkdf2_hmac_sha256_Final(pctx, key): 
    CLIB.pbkdf2_hmac_sha256_Final(ct.byref(pctx), key)


def pbkdf2_hmac_sha256_Final_r(): 
    pctx = (tt.PBKDF2_HMAC_SHA256_CTX)()
    key = (tt.uint8_t)()
    CLIB.pbkdf2_hmac_sha256_Final(ct.byref(pctx), key)
    return pctx, bytes(key)


def pbkdf2_hmac_sha256(pass_, passlen, salt, saltlen, iterations, key): 
    CLIB.pbkdf2_hmac_sha256(pass_, passlen, salt, saltlen, iterations, key)


def pbkdf2_hmac_sha256_r(pass_, passlen, salt, saltlen, iterations): 
    key = (tt.uint8_t)()
    CLIB.pbkdf2_hmac_sha256(pass_, passlen, salt, saltlen, iterations, key)
    return bytes(key)


def pbkdf2_hmac_sha512_Init(pctx, pass_, passlen, salt, saltlen): 
    CLIB.pbkdf2_hmac_sha512_Init(ct.byref(pctx), pass_, passlen, salt, saltlen)


def pbkdf2_hmac_sha512_Init_r(pass_, passlen, salt, saltlen): 
    pctx = (tt.PBKDF2_HMAC_SHA512_CTX)()
    CLIB.pbkdf2_hmac_sha512_Init(ct.byref(pctx), pass_, passlen, salt, saltlen)
    return pctx


def pbkdf2_hmac_sha512_Update(pctx, iterations): 
    CLIB.pbkdf2_hmac_sha512_Update(ct.byref(pctx), iterations)


def pbkdf2_hmac_sha512_Update_r(iterations): 
    pctx = (tt.PBKDF2_HMAC_SHA512_CTX)()
    CLIB.pbkdf2_hmac_sha512_Update(ct.byref(pctx), iterations)
    return pctx


def pbkdf2_hmac_sha512_Final(pctx, key): 
    CLIB.pbkdf2_hmac_sha512_Final(ct.byref(pctx), key)


def pbkdf2_hmac_sha512_Final_r(): 
    pctx = (tt.PBKDF2_HMAC_SHA512_CTX)()
    key = (tt.uint8_t)()
    CLIB.pbkdf2_hmac_sha512_Final(ct.byref(pctx), key)
    return pctx, bytes(key)


def pbkdf2_hmac_sha512(pass_, passlen, salt, saltlen, iterations, key): 
    CLIB.pbkdf2_hmac_sha512(pass_, passlen, salt, saltlen, iterations, key)


def pbkdf2_hmac_sha512_r(pass_, passlen, salt, saltlen, iterations): 
    key = (tt.uint8_t)()
    CLIB.pbkdf2_hmac_sha512(pass_, passlen, salt, saltlen, iterations, key)
    return bytes(key)


def read_be(data): 
    return int(CLIB.read_be(data))


def write_be(data, x): 
    CLIB.write_be(data, x)


def write_be_r(x): 
    data = (tt.uint8_t)()
    CLIB.write_be(data, x)
    return bytes(data)


def read_le(data): 
    return int(CLIB.read_le(data))


def write_le(data, x): 
    CLIB.write_le(data, x)


def write_le_r(x): 
    data = (tt.uint8_t)()
    CLIB.write_le(data, x)
    return bytes(data)


def bn_read_be(in_number, out_number): 
    CLIB.bn_read_be(in_number, ct.byref(out_number))


def bn_read_be_r(in_number): 
    out_number = (tt.bignum256)()
    CLIB.bn_read_be(in_number, ct.byref(out_number))
    return bytes(out_number)


def bn_write_be(in_number, out_number): 
    CLIB.bn_write_be(ct.byref(in_number), out_number)


def bn_write_be_r(in_number): 
    out_number = (tt.uint8_t)()
    CLIB.bn_write_be(ct.byref(in_number), out_number)
    return out_number


def bn_read_le(in_number, out_number): 
    CLIB.bn_read_le(in_number, ct.byref(out_number))


def bn_read_le_r(in_number): 
    out_number = (tt.bignum256)()
    CLIB.bn_read_le(in_number, ct.byref(out_number))
    return bytes(out_number)


def bn_write_le(in_number, out_number): 
    CLIB.bn_write_le(ct.byref(in_number), out_number)


def bn_write_le_r(in_number): 
    out_number = (tt.uint8_t)()
    CLIB.bn_write_le(ct.byref(in_number), out_number)
    return out_number


def bn_read_uint32(in_number, out_number): 
    CLIB.bn_read_uint32(in_number, ct.byref(out_number))


def bn_read_uint32_r(in_number): 
    out_number = (tt.bignum256)()
    CLIB.bn_read_uint32(in_number, ct.byref(out_number))
    return int(out_number)


def bn_read_uint64(in_number, out_number): 
    CLIB.bn_read_uint64(in_number, ct.byref(out_number))


def bn_read_uint64_r(in_number): 
    out_number = (tt.bignum256)()
    CLIB.bn_read_uint64(in_number, ct.byref(out_number))
    return int(out_number)


def bn_bitcount(a): 
    return int(CLIB.bn_bitcount(ct.byref(a)))


def bn_digitcount(a): 
    return int(CLIB.bn_digitcount(ct.byref(a)))


def bn_zero(a): 
    CLIB.bn_zero(ct.byref(a))


def bn_zero_r(): 
    a = (tt.bignum256)()
    CLIB.bn_zero(ct.byref(a))
    return a


def bn_is_zero(a): 
    return int(CLIB.bn_is_zero(ct.byref(a)))


def bn_one(a): 
    CLIB.bn_one(ct.byref(a))


def bn_one_r(): 
    a = (tt.bignum256)()
    CLIB.bn_one(ct.byref(a))
    return a


def bn_is_less(a, b): 
    return int(CLIB.bn_is_less(ct.byref(a), ct.byref(b)))


def bn_is_equal(a, b): 
    return int(CLIB.bn_is_equal(ct.byref(a), ct.byref(b)))


def bn_cmov(res, cond, truecase, falsecase): 
    CLIB.bn_cmov(ct.byref(res), cond, ct.byref(truecase), ct.byref(falsecase))


def bn_cmov_r(cond, truecase, falsecase): 
    res = (tt.bignum256)()
    CLIB.bn_cmov(ct.byref(res), cond, ct.byref(truecase), ct.byref(falsecase))
    return res


def bn_lshift(a): 
    CLIB.bn_lshift(ct.byref(a))


def bn_lshift_r(): 
    a = (tt.bignum256)()
    CLIB.bn_lshift(ct.byref(a))
    return a


def bn_rshift(a): 
    CLIB.bn_rshift(ct.byref(a))


def bn_rshift_r(): 
    a = (tt.bignum256)()
    CLIB.bn_rshift(ct.byref(a))
    return a


def bn_setbit(a, bit): 
    CLIB.bn_setbit(ct.byref(a), bit)


def bn_setbit_r(): 
    a = (tt.bignum256)()
    bit = (tt.uint8_t)()
    CLIB.bn_setbit(ct.byref(a), bit)
    return a, bit


def bn_clearbit(a, bit): 
    CLIB.bn_clearbit(ct.byref(a), bit)


def bn_clearbit_r(): 
    a = (tt.bignum256)()
    bit = (tt.uint8_t)()
    CLIB.bn_clearbit(ct.byref(a), bit)
    return a, bit


def bn_testbit(a, bit): 
    return int(CLIB.bn_testbit(ct.byref(a), bit))


def bn_testbit_r(): 
    a = (tt.bignum256)()
    bit = (tt.uint8_t)()
    _res = CLIB.bn_testbit(ct.byref(a), bit)
    return int(_res), a, bit


def bn_xor(a, b, c): 
    CLIB.bn_xor(ct.byref(a), ct.byref(b), ct.byref(c))


def bn_xor_r(b, c): 
    a = (tt.bignum256)()
    CLIB.bn_xor(ct.byref(a), ct.byref(b), ct.byref(c))
    return a


def bn_mult_half(x, prime): 
    CLIB.bn_mult_half(ct.byref(x), ct.byref(prime))


def bn_mult_half_r(prime): 
    x = (tt.bignum256)()
    CLIB.bn_mult_half(ct.byref(x), ct.byref(prime))
    return x


def bn_mult_k(x, k, prime): 
    CLIB.bn_mult_k(ct.byref(x), k, ct.byref(prime))


def bn_mult_k_r(prime): 
    x = (tt.bignum256)()
    k = (tt.uint8_t)()
    CLIB.bn_mult_k(ct.byref(x), k, ct.byref(prime))
    return x, k


def bn_mod(x, prime): 
    CLIB.bn_mod(ct.byref(x), ct.byref(prime))


def bn_mod_r(prime): 
    x = (tt.bignum256)()
    CLIB.bn_mod(ct.byref(x), ct.byref(prime))
    return x


def bn_multiply(k, x, prime): 
    CLIB.bn_multiply(ct.byref(k), ct.byref(x), ct.byref(prime))


def bn_fast_mod(x, prime): 
    CLIB.bn_fast_mod(ct.byref(x), ct.byref(prime))


def bn_fast_mod_r(prime): 
    x = (tt.bignum256)()
    CLIB.bn_fast_mod(ct.byref(x), ct.byref(prime))
    return x


def bn_sqrt(x, prime): 
    CLIB.bn_sqrt(ct.byref(x), ct.byref(prime))


def bn_sqrt_r(prime): 
    x = (tt.bignum256)()
    CLIB.bn_sqrt(ct.byref(x), ct.byref(prime))
    return x


def bn_inverse(x, prime): 
    CLIB.bn_inverse(ct.byref(x), ct.byref(prime))


def bn_inverse_r(prime): 
    x = (tt.bignum256)()
    CLIB.bn_inverse(ct.byref(x), ct.byref(prime))
    return x


def bn_normalize(a): 
    CLIB.bn_normalize(ct.byref(a))


def bn_normalize_r(): 
    a = (tt.bignum256)()
    CLIB.bn_normalize(ct.byref(a))
    return a


def bn_add(a, b): 
    CLIB.bn_add(ct.byref(a), ct.byref(b))


def bn_add_r(b): 
    a = (tt.bignum256)()
    CLIB.bn_add(ct.byref(a), ct.byref(b))
    return a


def bn_addmod(a, b, prime): 
    CLIB.bn_addmod(ct.byref(a), ct.byref(b), ct.byref(prime))


def bn_addmod_r(b, prime): 
    a = (tt.bignum256)()
    CLIB.bn_addmod(ct.byref(a), ct.byref(b), ct.byref(prime))
    return a


def bn_addi(a, b): 
    CLIB.bn_addi(ct.byref(a), b)


def bn_addi_r(b): 
    a = (tt.bignum256)()
    CLIB.bn_addi(ct.byref(a), b)
    return a


def bn_subi(a, b, prime): 
    CLIB.bn_subi(ct.byref(a), b, ct.byref(prime))


def bn_subi_r(b, prime): 
    a = (tt.bignum256)()
    CLIB.bn_subi(ct.byref(a), b, ct.byref(prime))
    return a


def bn_subtractmod(a, b, res, prime): 
    CLIB.bn_subtractmod(ct.byref(a), ct.byref(b), ct.byref(res), ct.byref(prime))


def bn_subtract(a, b, res): 
    CLIB.bn_subtract(ct.byref(a), ct.byref(b), ct.byref(res))


def bn_subtract_r(a, b): 
    res = (tt.bignum256)()
    CLIB.bn_subtract(ct.byref(a), ct.byref(b), ct.byref(res))
    return res


def bn_divmod58(a, r): 
    CLIB.bn_divmod58(ct.byref(a), ct.byref(r))


def bn_divmod58_r(): 
    a = (tt.bignum256)()
    r = (tt.uint32_t)()
    CLIB.bn_divmod58(ct.byref(a), ct.byref(r))
    return a, r


def bn_divmod1000(a, r): 
    CLIB.bn_divmod1000(ct.byref(a), ct.byref(r))


def bn_divmod1000_r(): 
    a = (tt.bignum256)()
    r = (tt.uint32_t)()
    CLIB.bn_divmod1000(ct.byref(a), ct.byref(r))
    return a, r


def bn_format(amnt, prefix, suffix, decimals, exponent, trailing, out, outlen): 
    return int(CLIB.bn_format(ct.byref(amnt), prefix, suffix, decimals, exponent, trailing, out, outlen))


def base32_encode(in_, inlen, out, outlen, alphabet): 
    return bytes(CLIB.base32_encode(in_, inlen, out, outlen, alphabet))


def base32_encode_unsafe(in_, inlen, out): 
    CLIB.base32_encode_unsafe(in_, inlen, out)


def base32_encode_unsafe_r(in_, inlen): 
    out = (tt.uint8_t)()
    CLIB.base32_encode_unsafe(in_, inlen, out)
    return bytes(out)


def base32_decode(in_, inlen, out, outlen, alphabet): 
    return bytes(CLIB.base32_decode(in_, inlen, out, outlen, alphabet))


def base32_decode_unsafe(in_, inlen, out, alphabet): 
    return int(CLIB.base32_decode_unsafe(in_, inlen, out, alphabet))


def base32_encoded_length(inlen): 
    return int(CLIB.base32_encoded_length(inlen))


def base32_decoded_length(inlen): 
    return int(CLIB.base32_decoded_length(inlen))


def base58_encode_check(data, len, hasher_type, str, strsize): 
    return int(CLIB.base58_encode_check(data, len, hasher_type, str, strsize))


def base58_decode_check(str, hasher_type, data, datalen): 
    return int(CLIB.base58_decode_check(str, hasher_type, data, datalen))


def b58tobin(bin, binszp, b58): 
    return int(CLIB.b58tobin(ct.byref(bin), ct.byref(binszp), b58))


def b58tobin_r(b58): 
    bin = (ct.c_void_p)()
    binszp = (tt.size_t)()
    _res = CLIB.b58tobin(ct.byref(bin), ct.byref(binszp), b58)
    return int(_res), bin, binszp


def b58check(bin, binsz, hasher_type, base58str): 
    return int(CLIB.b58check(ct.byref(bin), binsz, hasher_type, base58str))


def b58enc(b58, b58sz, data, binsz): 
    return int(CLIB.b58enc(b58, ct.byref(b58sz), ct.byref(data), binsz))


def b58enc_r(data, binsz): 
    b58 = (ct.c_byte)()
    b58sz = (tt.size_t)()
    _res = CLIB.b58enc(b58, ct.byref(b58sz), ct.byref(data), binsz)
    return int(_res), bytes(b58), b58sz


def xmr_base58_addr_encode_check(tag, data, binsz, b58, b58sz): 
    return int(CLIB.xmr_base58_addr_encode_check(tag, data, binsz, b58, b58sz))


def xmr_base58_addr_decode_check(addr, sz, tag, data, datalen): 
    return int(CLIB.xmr_base58_addr_decode_check(addr, sz, ct.byref(tag), ct.byref(data), datalen))


def xmr_base58_encode(b58, b58sz, data, binsz): 
    return int(CLIB.xmr_base58_encode(b58, ct.byref(b58sz), ct.byref(data), binsz))


def xmr_base58_encode_r(data, binsz): 
    b58 = (ct.c_byte)()
    b58sz = (tt.size_t)()
    _res = CLIB.xmr_base58_encode(b58, ct.byref(b58sz), ct.byref(data), binsz)
    return int(_res), bytes(b58), b58sz


def xmr_base58_decode(b58, b58sz, data, binsz): 
    return int(CLIB.xmr_base58_decode(b58, b58sz, ct.byref(data), ct.byref(binsz)))


def xmr_base58_decode_r(b58, b58sz): 
    data = (ct.c_void_p)()
    binsz = (tt.size_t)()
    _res = CLIB.xmr_base58_decode(b58, b58sz, ct.byref(data), ct.byref(binsz))
    return int(_res), bytes(data), int(binsz)


def curve25519_copy(out, in_): 
    CLIB.curve25519_copy(out, in_)


def curve25519_copy_r(in_): 
    out = (tt.bignum25519)()
    CLIB.curve25519_copy(out, in_)
    return out


def curve25519_add(out, a, b): 
    CLIB.curve25519_add(out, a, b)


def curve25519_add_r(a, b): 
    out = (tt.bignum25519)()
    CLIB.curve25519_add(out, a, b)
    return out


def curve25519_add_after_basic(out, a, b): 
    CLIB.curve25519_add_after_basic(out, a, b)


def curve25519_add_after_basic_r(a, b): 
    out = (tt.bignum25519)()
    CLIB.curve25519_add_after_basic(out, a, b)
    return out


def curve25519_add_reduce(out, a, b): 
    CLIB.curve25519_add_reduce(out, a, b)


def curve25519_add_reduce_r(a, b): 
    out = (tt.bignum25519)()
    CLIB.curve25519_add_reduce(out, a, b)
    return out


def curve25519_sub(out, a, b): 
    CLIB.curve25519_sub(out, a, b)


def curve25519_sub_r(a, b): 
    out = (tt.bignum25519)()
    CLIB.curve25519_sub(out, a, b)
    return out


def curve25519_scalar_product(out, in_, scalar): 
    CLIB.curve25519_scalar_product(out, in_, scalar)


def curve25519_scalar_product_r(in_, scalar): 
    out = (tt.bignum25519)()
    CLIB.curve25519_scalar_product(out, in_, scalar)
    return out


def curve25519_sub_after_basic(out, a, b): 
    CLIB.curve25519_sub_after_basic(out, a, b)


def curve25519_sub_after_basic_r(a, b): 
    out = (tt.bignum25519)()
    CLIB.curve25519_sub_after_basic(out, a, b)
    return out


def curve25519_sub_reduce(out, a, b): 
    CLIB.curve25519_sub_reduce(out, a, b)


def curve25519_sub_reduce_r(a, b): 
    out = (tt.bignum25519)()
    CLIB.curve25519_sub_reduce(out, a, b)
    return out


def curve25519_neg(out, a): 
    CLIB.curve25519_neg(out, a)


def curve25519_neg_r(a): 
    out = (tt.bignum25519)()
    CLIB.curve25519_neg(out, a)
    return out


def curve25519_mul(out, a, b): 
    CLIB.curve25519_mul(out, a, b)


def curve25519_mul_r(a, b): 
    out = (tt.bignum25519)()
    CLIB.curve25519_mul(out, a, b)
    return out


def curve25519_square(out, in_): 
    CLIB.curve25519_square(out, in_)


def curve25519_square_r(in_): 
    out = (tt.bignum25519)()
    CLIB.curve25519_square(out, in_)
    return out


def curve25519_square_times(out, in_, count): 
    CLIB.curve25519_square_times(out, in_, count)


def curve25519_square_times_r(in_, count): 
    out = (tt.bignum25519)()
    CLIB.curve25519_square_times(out, in_, count)
    return out


def curve25519_expand(out, in_): 
    CLIB.curve25519_expand(out, in_)


def curve25519_expand_r(in_): 
    out = (tt.bignum25519)()
    CLIB.curve25519_expand(out, in_)
    return out


def curve25519_contract(out, in_): 
    CLIB.curve25519_contract(out, in_)


def curve25519_contract_r(in_): 
    out = (ct.c_ubyte * 32)()
    CLIB.curve25519_contract(out, in_)
    return bytes(out)


def curve25519_swap_conditional(a, b, iswap): 
    CLIB.curve25519_swap_conditional(a, b, iswap)


def curve25519_swap_conditional_r(iswap): 
    a = (tt.bignum25519)()
    b = (tt.bignum25519)()
    CLIB.curve25519_swap_conditional(a, b, iswap)
    return a, b


def curve25519_pow_two5mtwo0_two250mtwo0(b): 
    CLIB.curve25519_pow_two5mtwo0_two250mtwo0(b)


def curve25519_pow_two5mtwo0_two250mtwo0_r(): 
    b = (tt.bignum25519)()
    CLIB.curve25519_pow_two5mtwo0_two250mtwo0(b)
    return b


def curve25519_recip(out, z): 
    CLIB.curve25519_recip(out, z)


def curve25519_recip_r(z): 
    out = (tt.bignum25519)()
    CLIB.curve25519_recip(out, z)
    return out


def curve25519_pow_two252m3(two252m3, z): 
    CLIB.curve25519_pow_two252m3(two252m3, z)


def curve25519_pow_two252m3_r(z): 
    two252m3 = (tt.bignum25519)()
    CLIB.curve25519_pow_two252m3(two252m3, z)
    return two252m3


def reduce256_modm(r): 
    CLIB.reduce256_modm(r)


def reduce256_modm_r(): 
    r = (tt.bignum256modm)()
    CLIB.reduce256_modm(r)
    return r


def barrett_reduce256_modm(r, q1, r1): 
    CLIB.barrett_reduce256_modm(r, q1, r1)


def barrett_reduce256_modm_r(q1, r1): 
    r = (tt.bignum256modm)()
    CLIB.barrett_reduce256_modm(r, q1, r1)
    return r


def add256_modm(r, x, y): 
    CLIB.add256_modm(r, x, y)


def add256_modm_r(x, y): 
    r = (tt.bignum256modm)()
    CLIB.add256_modm(r, x, y)
    return r


def neg256_modm(r, x): 
    CLIB.neg256_modm(r, x)


def neg256_modm_r(x): 
    r = (tt.bignum256modm)()
    CLIB.neg256_modm(r, x)
    return r


def sub256_modm(r, x, y): 
    CLIB.sub256_modm(r, x, y)


def sub256_modm_r(x, y): 
    r = (tt.bignum256modm)()
    CLIB.sub256_modm(r, x, y)
    return r


def mul256_modm(r, x, y): 
    CLIB.mul256_modm(r, x, y)


def mul256_modm_r(x, y): 
    r = (tt.bignum256modm)()
    CLIB.mul256_modm(r, x, y)
    return r


def expand_raw256_modm(out, in_): 
    CLIB.expand_raw256_modm(out, in_)


def expand_raw256_modm_r(in_): 
    out = (tt.bignum256modm)()
    CLIB.expand_raw256_modm(out, in_)
    return out


def contract256_modm(out, in_): 
    CLIB.contract256_modm(out, in_)


def contract256_modm_r(in_): 
    out = (ct.c_ubyte * 32)()
    CLIB.contract256_modm(out, in_)
    return bytes(out)


def contract256_window4_modm(r, in_): 
    CLIB.contract256_window4_modm(r, in_)


def contract256_window4_modm_r(in_): 
    r = (ct.c_byte * 64)()
    CLIB.contract256_window4_modm(r, in_)
    return bytes(r)


def contract256_slidingwindow_modm(r, s, windowsize): 
    CLIB.contract256_slidingwindow_modm(r, s, windowsize)


def contract256_slidingwindow_modm_r(s, windowsize): 
    r = (ct.c_byte * 256)()
    CLIB.contract256_slidingwindow_modm(r, s, windowsize)
    return bytes(r)


def ed25519_verify(x, y, len): 
    return int(CLIB.ed25519_verify(x, y, len))


def ge25519_p1p1_to_partial(r, p): 
    CLIB.ge25519_p1p1_to_partial(ct.byref(r), ct.byref(p))


def ge25519_p1p1_to_partial_r(p): 
    r = (tt.ge25519)()
    CLIB.ge25519_p1p1_to_partial(ct.byref(r), ct.byref(p))
    return r


def ge25519_p1p1_to_full(r, p): 
    CLIB.ge25519_p1p1_to_full(ct.byref(r), ct.byref(p))


def ge25519_p1p1_to_full_r(p): 
    r = (tt.ge25519)()
    CLIB.ge25519_p1p1_to_full(ct.byref(r), ct.byref(p))
    return r


def ge25519_full_to_pniels(p, r): 
    CLIB.ge25519_full_to_pniels(ct.byref(p), ct.byref(r))


def ge25519_full_to_pniels_r(r): 
    p = (tt.ge25519_pniels)()
    CLIB.ge25519_full_to_pniels(ct.byref(p), ct.byref(r))
    return p


def ge25519_double_p1p1(r, p): 
    CLIB.ge25519_double_p1p1(ct.byref(r), ct.byref(p))


def ge25519_double_p1p1_r(p): 
    r = (tt.ge25519_p1p1)()
    CLIB.ge25519_double_p1p1(ct.byref(r), ct.byref(p))
    return r


def ge25519_nielsadd2_p1p1(r, p, q, signbit): 
    CLIB.ge25519_nielsadd2_p1p1(ct.byref(r), ct.byref(p), ct.byref(q), signbit)


def ge25519_nielsadd2_p1p1_r(p, q, signbit): 
    r = (tt.ge25519_p1p1)()
    CLIB.ge25519_nielsadd2_p1p1(ct.byref(r), ct.byref(p), ct.byref(q), signbit)
    return r


def ge25519_pnielsadd_p1p1(r, p, q, signbit): 
    CLIB.ge25519_pnielsadd_p1p1(ct.byref(r), ct.byref(p), ct.byref(q), signbit)


def ge25519_pnielsadd_p1p1_r(p, q, signbit): 
    r = (tt.ge25519_p1p1)()
    CLIB.ge25519_pnielsadd_p1p1(ct.byref(r), ct.byref(p), ct.byref(q), signbit)
    return r


def ge25519_double_partial(r, p): 
    CLIB.ge25519_double_partial(ct.byref(r), ct.byref(p))


def ge25519_double_partial_r(p): 
    r = (tt.ge25519)()
    CLIB.ge25519_double_partial(ct.byref(r), ct.byref(p))
    return r


def ge25519_double(r, p): 
    CLIB.ge25519_double(ct.byref(r), ct.byref(p))


def ge25519_double_r(p): 
    r = (tt.ge25519)()
    CLIB.ge25519_double(ct.byref(r), ct.byref(p))
    return r


def ge25519_nielsadd2(r, q): 
    CLIB.ge25519_nielsadd2(ct.byref(r), ct.byref(q))


def ge25519_nielsadd2_r(q): 
    r = (tt.ge25519)()
    CLIB.ge25519_nielsadd2(ct.byref(r), ct.byref(q))
    return r


def ge25519_pnielsadd(r, p, q): 
    CLIB.ge25519_pnielsadd(ct.byref(r), ct.byref(p), ct.byref(q))


def ge25519_pnielsadd_r(p, q): 
    r = (tt.ge25519_pniels)()
    CLIB.ge25519_pnielsadd(ct.byref(r), ct.byref(p), ct.byref(q))
    return r


def ge25519_pack(r, p): 
    CLIB.ge25519_pack(r, ct.byref(p))


def ge25519_pack_r(p): 
    r = (ct.c_ubyte * 32)()
    CLIB.ge25519_pack(r, ct.byref(p))
    return bytes(r)


def ge25519_unpack_negative_vartime(r, p): 
    return int(CLIB.ge25519_unpack_negative_vartime(ct.byref(r), p))


def ge25519_unpack_negative_vartime_r(p): 
    r = (tt.ge25519)()
    _res = CLIB.ge25519_unpack_negative_vartime(ct.byref(r), p)
    return int(_res), r


def ge25519_set_neutral(r): 
    CLIB.ge25519_set_neutral(ct.byref(r))


def ge25519_set_neutral_r(): 
    r = (tt.ge25519)()
    CLIB.ge25519_set_neutral(ct.byref(r))
    return r


def ge25519_double_scalarmult_vartime(r, p1, s1, s2): 
    CLIB.ge25519_double_scalarmult_vartime(ct.byref(r), ct.byref(p1), s1, s2)


def ge25519_double_scalarmult_vartime_r(p1, s1, s2): 
    r = (tt.ge25519)()
    CLIB.ge25519_double_scalarmult_vartime(ct.byref(r), ct.byref(p1), s1, s2)
    return r


def ge25519_double_scalarmult_vartime2(r, p1, s1, p2, s2): 
    CLIB.ge25519_double_scalarmult_vartime2(ct.byref(r), ct.byref(p1), s1, ct.byref(p2), s2)


def ge25519_double_scalarmult_vartime2_r(p1, s1, p2, s2): 
    r = (tt.ge25519)()
    CLIB.ge25519_double_scalarmult_vartime2(ct.byref(r), ct.byref(p1), s1, ct.byref(p2), s2)
    return r


def ge25519_scalarmult(r, p1, s1): 
    CLIB.ge25519_scalarmult(ct.byref(r), ct.byref(p1), s1)


def ge25519_scalarmult_r(p1, s1): 
    r = (tt.ge25519)()
    CLIB.ge25519_scalarmult(ct.byref(r), ct.byref(p1), s1)
    return r


def set256_modm(r, v): 
    CLIB.set256_modm(r, v)


def set256_modm_r(v): 
    r = (tt.bignum256modm)()
    CLIB.set256_modm(r, v)
    return r


def get256_modm(v, r): 
    return int(CLIB.get256_modm(ct.byref(v), r))


def eq256_modm(x, y): 
    return int(CLIB.eq256_modm(x, y))


def cmp256_modm(x, y): 
    return int(CLIB.cmp256_modm(x, y))


def iszero256_modm(x): 
    return int(CLIB.iszero256_modm(x))


def copy256_modm(r, x): 
    CLIB.copy256_modm(r, x)


def copy256_modm_r(x): 
    r = (tt.bignum256modm)()
    CLIB.copy256_modm(r, x)
    return r


def check256_modm(x): 
    return int(CLIB.check256_modm(x))


def mulsub256_modm(r, a, b, c): 
    CLIB.mulsub256_modm(r, a, b, c)


def mulsub256_modm_r(a, b, c): 
    r = (tt.bignum256modm)()
    CLIB.mulsub256_modm(r, a, b, c)
    return r


def muladd256_modm(r, a, b, c): 
    CLIB.muladd256_modm(r, a, b, c)


def muladd256_modm_r(a, b, c): 
    r = (tt.bignum256modm)()
    CLIB.muladd256_modm(r, a, b, c)
    return r


def curve25519_set(r, x): 
    CLIB.curve25519_set(r, x)


def curve25519_set_r(x): 
    r = (tt.bignum25519)()
    CLIB.curve25519_set(r, x)
    return r


def curve25519_set_d(r): 
    CLIB.curve25519_set_d(r)


def curve25519_set_d_r(): 
    r = (tt.bignum25519)()
    CLIB.curve25519_set_d(r)
    return r


def curve25519_set_2d(r): 
    CLIB.curve25519_set_2d(r)


def curve25519_set_2d_r(): 
    r = (tt.bignum25519)()
    CLIB.curve25519_set_2d(r)
    return r


def curve25519_set_sqrtneg1(r): 
    CLIB.curve25519_set_sqrtneg1(r)


def curve25519_set_sqrtneg1_r(): 
    r = (tt.bignum25519)()
    CLIB.curve25519_set_sqrtneg1(r)
    return r


def curve25519_isnegative(f): 
    return int(CLIB.curve25519_isnegative(f))


def curve25519_isnonzero(f): 
    return int(CLIB.curve25519_isnonzero(f))


def curve25519_reduce(r, in_): 
    CLIB.curve25519_reduce(r, in_)


def curve25519_reduce_r(in_): 
    r = (tt.bignum25519)()
    CLIB.curve25519_reduce(r, in_)
    return r


def curve25519_expand_reduce(out, in_): 
    CLIB.curve25519_expand_reduce(out, in_)


def curve25519_expand_reduce_r(in_): 
    out = (tt.bignum25519)()
    CLIB.curve25519_expand_reduce(out, in_)
    return out


def ge25519_check(r): 
    return int(CLIB.ge25519_check(ct.byref(r)))


def ge25519_fromfe_check(r): 
    return int(CLIB.ge25519_fromfe_check(ct.byref(r)))


def ge25519_eq(a, b): 
    return int(CLIB.ge25519_eq(ct.byref(a), ct.byref(b)))


def ge25519_copy(dst, src): 
    CLIB.ge25519_copy(ct.byref(dst), ct.byref(src))


def ge25519_copy_r(src): 
    dst = (tt.ge25519)()
    CLIB.ge25519_copy(ct.byref(dst), ct.byref(src))
    return dst


def ge25519_set_base(r): 
    CLIB.ge25519_set_base(ct.byref(r))


def ge25519_set_base_r(): 
    r = (tt.ge25519)()
    CLIB.ge25519_set_base(ct.byref(r))
    return r


def ge25519_mul8(r, t): 
    CLIB.ge25519_mul8(ct.byref(r), ct.byref(t))


def ge25519_mul8_r(t): 
    r = (tt.ge25519)()
    CLIB.ge25519_mul8(ct.byref(r), ct.byref(t))
    return r


def ge25519_neg_partial(r): 
    CLIB.ge25519_neg_partial(ct.byref(r))


def ge25519_neg_partial_r(): 
    r = (tt.ge25519)()
    CLIB.ge25519_neg_partial(ct.byref(r))
    return r


def ge25519_neg_full(r): 
    CLIB.ge25519_neg_full(ct.byref(r))


def ge25519_neg_full_r(): 
    r = (tt.ge25519)()
    CLIB.ge25519_neg_full(ct.byref(r))
    return r


def ge25519_reduce(r, t): 
    CLIB.ge25519_reduce(ct.byref(r), ct.byref(t))


def ge25519_reduce_r(t): 
    r = (tt.ge25519)()
    CLIB.ge25519_reduce(ct.byref(r), ct.byref(t))
    return r


def ge25519_norm(r, t): 
    CLIB.ge25519_norm(ct.byref(r), ct.byref(t))


def ge25519_norm_r(t): 
    r = (tt.ge25519)()
    CLIB.ge25519_norm(ct.byref(r), ct.byref(t))
    return r


def ge25519_add(r, a, b, signbit): 
    CLIB.ge25519_add(ct.byref(r), ct.byref(a), ct.byref(b), signbit)


def ge25519_add_r(a, b, signbit): 
    r = (tt.ge25519)()
    CLIB.ge25519_add(ct.byref(r), ct.byref(a), ct.byref(b), signbit)
    return r


def ge25519_fromfe_frombytes_vartime(r, s): 
    CLIB.ge25519_fromfe_frombytes_vartime(ct.byref(r), s)


def ge25519_fromfe_frombytes_vartime_r(s): 
    r = (tt.ge25519)()
    CLIB.ge25519_fromfe_frombytes_vartime(ct.byref(r), s)
    return r


def ge25519_unpack_vartime(r, s): 
    return int(CLIB.ge25519_unpack_vartime(ct.byref(r), s))


def ge25519_scalarmult_base_wrapper(r, s): 
    CLIB.ge25519_scalarmult_base_wrapper(ct.byref(r), s)


def ge25519_scalarmult_base_wrapper_r(s): 
    r = (tt.ge25519)()
    CLIB.ge25519_scalarmult_base_wrapper(ct.byref(r), s)
    return r


def ge25519_scalarmult_wrapper(r, P, a): 
    CLIB.ge25519_scalarmult_wrapper(ct.byref(r), ct.byref(P), a)


def ge25519_scalarmult_wrapper_r(P, a): 
    r = (tt.ge25519)()
    CLIB.ge25519_scalarmult_wrapper(ct.byref(r), ct.byref(P), a)
    return r


def xmr_size_varint(num): 
    return int(CLIB.xmr_size_varint(num))


def xmr_write_varint(buff, buff_size, num): 
    return int(CLIB.xmr_write_varint(buff, buff_size, num))


def xmr_write_varint_r(buff_size, num): 
    buff = (tt.uint8_t)()
    _res = CLIB.xmr_write_varint(buff, buff_size, num)
    return int(_res), bytes(buff)


def xmr_read_varint(buff, buff_size, val): 
    return int(CLIB.xmr_read_varint(buff, buff_size, ct.byref(val)))


def xmr_read_varint_r(buff_size, val): 
    buff = (tt.uint8_t)()
    _res = CLIB.xmr_read_varint(buff, buff_size, ct.byref(val))
    return int(_res), bytes(buff)


def ge25519_set_xmr_h(r): 
    CLIB.ge25519_set_xmr_h(ct.byref(r))


def ge25519_set_xmr_h_r(): 
    r = (tt.ge25519)()
    CLIB.ge25519_set_xmr_h(ct.byref(r))
    return r


def xmr_random_scalar(m): 
    CLIB.xmr_random_scalar(m)


def xmr_random_scalar_r(): 
    m = (tt.bignum256modm)()
    CLIB.xmr_random_scalar(m)
    return m


def xmr_fast_hash(hash, data, length): 
    CLIB.xmr_fast_hash(hash, ct.byref(data), length)


def xmr_hasher_init(hasher): 
    CLIB.xmr_hasher_init(ct.byref(hasher))


def xmr_hasher_init_r(): 
    hasher = (tt.Hasher)()
    CLIB.xmr_hasher_init(ct.byref(hasher))
    return hasher


def xmr_hasher_final(hasher, hash): 
    CLIB.xmr_hasher_final(ct.byref(hasher), hash)


def xmr_hasher_final_r(hasher): 
    hash = tt.KEY_BUFF()
    CLIB.xmr_hasher_final(ct.byref(hasher), hash)
    return bytes(hash)

def xmr_hasher_copy(dst, src): 
    CLIB.xmr_hasher_copy(ct.byref(dst), ct.byref(src))


def xmr_hasher_copy_r(src): 
    dst = (tt.Hasher)()
    CLIB.xmr_hasher_copy(ct.byref(dst), ct.byref(src))
    return dst


def xmr_derivation_to_scalar(s, p, output_index): 
    CLIB.xmr_derivation_to_scalar(s, ct.byref(p), output_index)


def xmr_derivation_to_scalar_r(p, output_index): 
    s = (tt.bignum256modm)()
    CLIB.xmr_derivation_to_scalar(s, ct.byref(p), output_index)
    return s


def xmr_generate_key_derivation(r, A, b): 
    CLIB.xmr_generate_key_derivation(ct.byref(r), ct.byref(A), b)


def xmr_generate_key_derivation_r(A, b): 
    r = (tt.ge25519)()
    CLIB.xmr_generate_key_derivation(ct.byref(r), ct.byref(A), b)
    return r


def xmr_derive_private_key(s, deriv, idx, base): 
    CLIB.xmr_derive_private_key(s, ct.byref(deriv), idx, base)


def xmr_derive_private_key_r(deriv, idx, base): 
    s = (tt.bignum256modm)()
    CLIB.xmr_derive_private_key(s, ct.byref(deriv), idx, base)
    return s


def xmr_derive_public_key(r, deriv, idx, base): 
    CLIB.xmr_derive_public_key(ct.byref(r), ct.byref(deriv), idx, ct.byref(base))


def xmr_derive_public_key_r(deriv, idx, base): 
    r = (tt.ge25519)()
    CLIB.xmr_derive_public_key(ct.byref(r), ct.byref(deriv), idx, ct.byref(base))
    return r


def xmr_add_keys2(r, a, b, B): 
    CLIB.xmr_add_keys2(ct.byref(r), a, b, ct.byref(B))


def xmr_add_keys2_r(a, b, B): 
    r = (tt.ge25519)()
    CLIB.xmr_add_keys2(ct.byref(r), a, b, ct.byref(B))
    return r


def xmr_add_keys2_vartime(r, a, b, B): 
    CLIB.xmr_add_keys2_vartime(ct.byref(r), a, b, ct.byref(B))


def xmr_add_keys2_vartime_r(a, b, B): 
    r = (tt.ge25519)()
    CLIB.xmr_add_keys2_vartime(ct.byref(r), a, b, ct.byref(B))
    return r


def xmr_add_keys3(r, a, A, b, B): 
    CLIB.xmr_add_keys3(ct.byref(r), a, ct.byref(A), b, ct.byref(B))


def xmr_add_keys3_r(a, A, b, B): 
    r = (tt.ge25519)()
    CLIB.xmr_add_keys3(ct.byref(r), a, ct.byref(A), b, ct.byref(B))
    return r


def xmr_add_keys3_vartime(r, a, A, b, B): 
    CLIB.xmr_add_keys3_vartime(ct.byref(r), a, ct.byref(A), b, ct.byref(B))


def xmr_add_keys3_vartime_r(a, A, b, B): 
    r = (tt.ge25519)()
    CLIB.xmr_add_keys3_vartime(ct.byref(r), a, ct.byref(A), b, ct.byref(B))
    return r


def xmr_get_subaddress_secret_key(r, major, minor, m): 
    CLIB.xmr_get_subaddress_secret_key(r, major, minor, m)


def xmr_get_subaddress_secret_key_r(major, minor, m): 
    r = (tt.bignum256modm)()
    CLIB.xmr_get_subaddress_secret_key(r, major, minor, m)
    return r


def xmr_gen_c(r, a, amount): 
    CLIB.xmr_gen_c(ct.byref(r), a, amount)


def xmr_gen_c_r(a, amount): 
    r = (tt.ge25519)()
    CLIB.xmr_gen_c(ct.byref(r), a, amount)
    return r


def xmr_gen_range_sig(sig, C, mask, amount, last_mask): 
    CLIB.xmr_gen_range_sig(ct.byref(sig), ct.byref(C), mask, amount, ct.byref(last_mask))


def xmr_gen_range_sig_r(amount, last_mask): 
    sig = (tt.xmr_range_sig_t)()
    C = (tt.ge25519)()
    mask = (tt.bignum256modm)()
    CLIB.xmr_gen_range_sig(ct.byref(sig), ct.byref(C), mask, amount, ct.byref(last_mask))
    return sig, C, mask




