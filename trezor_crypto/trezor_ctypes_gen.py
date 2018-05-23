# -*- coding: utf-8 -*-
#
# TARGET arch is: ["'--std=c99", '-fPIC', '-DUSE_MONERO=1', '-DUSE_KECCAK=1', '-DUSE_LIBSODIUM', '-DSODIUM_STATIC=1', '-DRAND_PLATFORM_INDEPENDENT=1', '-Isrc/', "-I/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/9.1.0/include/'"]
# WORD_SIZE is: 8
# POINTER_SIZE is: 8
# LONGDOUBLE_SIZE is: 16
#
import ctypes


c_int128 = ctypes.c_ubyte*16
c_uint128 = c_int128
void = None
if ctypes.sizeof(ctypes.c_longdouble) == 16:
    c_long_double_t = ctypes.c_longdouble
else:
    c_long_double_t = ctypes.c_ubyte*16

# if local wordsize is same as target, keep ctypes pointer function.
if ctypes.sizeof(ctypes.c_void_p) == 8:
    POINTER_T = ctypes.POINTER
else:
    # required to access _ctypes
    import _ctypes
    # Emulate a pointer class using the approriate c_int32/c_int64 type
    # The new class should have :
    # ['__module__', 'from_param', '_type_', '__dict__', '__weakref__', '__doc__']
    # but the class should be submitted to a unique instance for each base type
    # to that if A == B, POINTER_T(A) == POINTER_T(B)
    ctypes._pointer_t_type_cache = {}
    def POINTER_T(pointee):
        # a pointer should have the same length as LONG
        fake_ptr_base_type = ctypes.c_uint64 
        # specific case for c_void_p
        if pointee is None: # VOID pointer type. c_void_p.
            pointee = type(None) # ctypes.c_void_p # ctypes.c_ulong
            clsname = 'c_void'
        else:
            clsname = pointee.__name__
        if clsname in ctypes._pointer_t_type_cache:
            return ctypes._pointer_t_type_cache[clsname]
        # make template
        class _T(_ctypes._SimpleCData,):
            _type_ = 'L'
            _subtype_ = pointee
            def _sub_addr_(self):
                return self.value
            def __repr__(self):
                return '%s(%d)'%(clsname, self.value)
            def contents(self):
                raise TypeError('This is not a ctypes pointer.')
            def __init__(self, **args):
                raise TypeError('This is not a ctypes pointer. It is not instanciable.')
        _class = type('LP_%d_%s'%(8, clsname), (_T,),{}) 
        ctypes._pointer_t_type_cache[clsname] = _class
        return _class



uint32_t = ctypes.c_uint32
uint64_t = ctypes.c_uint64
uint8_t = ctypes.c_uint8
int32_t = ctypes.c_int32
size_t = ctypes.c_uint64
class union_c__UA_aes_inf(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('l', ctypes.c_uint32),
    ('b', ctypes.c_ubyte * 4),
     ]

aes_inf = union_c__UA_aes_inf
class struct_c__SA_aes_encrypt_ctx(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ks', ctypes.c_uint32 * 60),
    ('inf', aes_inf),
    ('PADDING_0', ctypes.c_ubyte * 12),
     ]

aes_encrypt_ctx = struct_c__SA_aes_encrypt_ctx
class struct_c__SA_aes_decrypt_ctx(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ks', ctypes.c_uint32 * 60),
    ('inf', aes_inf),
    ('PADDING_0', ctypes.c_ubyte * 12),
     ]

aes_decrypt_ctx = struct_c__SA_aes_decrypt_ctx
cbuf_inc = ctypes.CFUNCTYPE(None, POINTER_T(ctypes.c_ubyte))
t_rc = None # Variable ctypes.c_int32
BASE32_ALPHABET_RFC4648 = None # Variable POINTER_T(ctypes.c_char)
class struct_c__SA_bignum256(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('val', ctypes.c_uint32 * 9),
     ]

bignum256 = struct_c__SA_bignum256
class struct_c__SA_curve_info(ctypes.Structure):
    pass

class struct_c__SA_ecdsa_curve(ctypes.Structure):
    pass

class struct_c__SA_curve_point(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('x', bignum256),
    ('y', bignum256),
     ]

curve_point = struct_c__SA_curve_point
struct_c__SA_ecdsa_curve._pack_ = True # source:False
struct_c__SA_ecdsa_curve._fields_ = [
    ('prime', bignum256),
    ('G', curve_point),
    ('order', bignum256),
    ('order_half', bignum256),
    ('a', ctypes.c_int32),
    ('b', bignum256),
    ('cp', struct_c__SA_curve_point * 8 * 64),
]


# values for enumeration 'c__EA_HasherType'
HASHER_SHA2 = 0
HASHER_BLAKE = 1
HASHER_SHA2D = 2
HASHER_BLAKED = 3
HASHER_GROESTLD_TRUNC = 4
HASHER_SHA3 = 5
HASHER_SHA3K = 6
c__EA_HasherType = ctypes.c_int # enum
HasherType = c__EA_HasherType
struct_c__SA_curve_info._pack_ = True # source:False
struct_c__SA_curve_info._fields_ = [
    ('bip32_name', POINTER_T(ctypes.c_char)),
    ('params', POINTER_T(struct_c__SA_ecdsa_curve)),
    ('hasher_bip32', HasherType),
    ('hasher_base58', HasherType),
    ('hasher_sign', HasherType),
    ('hasher_pubkey', HasherType),
]

curve_info = struct_c__SA_curve_info
class struct_c__SA_HDNode(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('depth', ctypes.c_uint32),
    ('child_num', ctypes.c_uint32),
    ('chain_code', ctypes.c_ubyte * 32),
    ('private_key', ctypes.c_ubyte * 32),
    ('public_key', ctypes.c_ubyte * 33),
    ('PADDING_0', ctypes.c_ubyte * 7),
    ('curve', POINTER_T(struct_c__SA_curve_info)),
     ]

HDNode = struct_c__SA_HDNode
wordlist = POINTER_T(ctypes.c_char) * 2049 # Variable POINTER_T(ctypes.c_char) * 2049
class struct_c__SA_BLAKE256_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('h', ctypes.c_uint32 * 8),
    ('s', ctypes.c_uint32 * 4),
    ('t', ctypes.c_uint32 * 2),
    ('buflen', ctypes.c_uint64),
    ('nullt', ctypes.c_ubyte),
    ('buf', ctypes.c_ubyte * 64),
    ('PADDING_0', ctypes.c_ubyte * 7),
     ]

BLAKE256_CTX = struct_c__SA_BLAKE256_CTX

# values for enumeration 'blake2b_constant'
BLAKE2B_BLOCKBYTES = 128
BLAKE2B_OUTBYTES = 64
BLAKE2B_KEYBYTES = 64
BLAKE2B_SALTBYTES = 16
BLAKE2B_PERSONALBYTES = 16
blake2b_constant = ctypes.c_int # enum
class struct___blake2b_state(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('h', ctypes.c_uint64 * 8),
    ('t', ctypes.c_uint64 * 2),
    ('f', ctypes.c_uint64 * 2),
    ('buf', ctypes.c_ubyte * 128),
    ('buflen', ctypes.c_uint64),
    ('outlen', ctypes.c_uint64),
    ('last_node', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 7),
     ]

blake2b_state = struct___blake2b_state

# values for enumeration 'blake2s_constant'
BLAKE2S_BLOCKBYTES = 64
BLAKE2S_OUTBYTES = 32
BLAKE2S_KEYBYTES = 32
BLAKE2S_SALTBYTES = 8
BLAKE2S_PERSONALBYTES = 8
blake2s_constant = ctypes.c_int # enum
class struct___blake2s_state(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('h', ctypes.c_uint32 * 8),
    ('t', ctypes.c_uint32 * 2),
    ('f', ctypes.c_uint32 * 2),
    ('buf', ctypes.c_ubyte * 64),
    ('buflen', ctypes.c_uint32),
    ('outlen', ctypes.c_ubyte),
    ('last_node', ctypes.c_ubyte),
    ('PADDING_0', ctypes.c_ubyte * 2),
     ]

blake2s_state = struct___blake2s_state
SECP256K1_NAME = [] # Variable ctypes.c_char * 0
SECP256K1_DECRED_NAME = [] # Variable ctypes.c_char * 0
SECP256K1_GROESTL_NAME = [] # Variable ctypes.c_char * 0
NIST256P1_NAME = [] # Variable ctypes.c_char * 0
ED25519_NAME = [] # Variable ctypes.c_char * 0
ED25519_SHA3_NAME = [] # Variable ctypes.c_char * 0
ED25519_KECCAK_NAME = [] # Variable ctypes.c_char * 0
CURVE25519_NAME = [] # Variable ctypes.c_char * 0
ecdsa_curve = struct_c__SA_ecdsa_curve
bignum25519 = ctypes.c_uint32 * 10
hash_512bits = ctypes.c_ubyte * 64
class struct_ge25519_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('x', ctypes.c_uint32 * 10),
    ('y', ctypes.c_uint32 * 10),
    ('z', ctypes.c_uint32 * 10),
    ('t', ctypes.c_uint32 * 10),
     ]

ge25519 = struct_ge25519_t
class struct_ge25519_p1p1_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('x', ctypes.c_uint32 * 10),
    ('y', ctypes.c_uint32 * 10),
    ('z', ctypes.c_uint32 * 10),
    ('t', ctypes.c_uint32 * 10),
     ]

ge25519_p1p1 = struct_ge25519_p1p1_t
class struct_ge25519_niels_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ysubx', ctypes.c_uint32 * 10),
    ('xaddy', ctypes.c_uint32 * 10),
    ('t2d', ctypes.c_uint32 * 10),
     ]

ge25519_niels = struct_ge25519_niels_t
class struct_ge25519_pniels_t(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('ysubx', ctypes.c_uint32 * 10),
    ('xaddy', ctypes.c_uint32 * 10),
    ('z', ctypes.c_uint32 * 10),
    ('t2d', ctypes.c_uint32 * 10),
     ]

ge25519_pniels = struct_ge25519_pniels_t
ed25519_signature = ctypes.c_ubyte * 64
ed25519_public_key = ctypes.c_ubyte * 32
ed25519_secret_key = ctypes.c_ubyte * 32
bignum256modm = ctypes.c_uint32 * 9
class struct_c__SA_sph_groestl_big_context(ctypes.Structure):
    pass

class union_c__SA_sph_groestl_big_context_0(ctypes.Union):
    _pack_ = True # source:False
    _fields_ = [
    ('wide', ctypes.c_uint64 * 16),
    ('narrow', ctypes.c_uint32 * 32),
     ]

struct_c__SA_sph_groestl_big_context._pack_ = True # source:False
struct_c__SA_sph_groestl_big_context._fields_ = [
    ('buf', ctypes.c_ubyte * 128),
    ('ptr', ctypes.c_uint64),
    ('state', union_c__SA_sph_groestl_big_context_0),
    ('count', ctypes.c_uint64),
]

class struct_c_groestlDOTh_S_groestlDOTh_2155(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('PADDING_0', ctypes.c_ubyte),
     ]

sph_groestl_big_context = struct_c__SA_sph_groestl_big_context
GROESTL512_CTX = struct_c__SA_sph_groestl_big_context
sph_u32 = ctypes.c_uint32
sph_s32 = ctypes.c_int32
sph_u64 = ctypes.c_uint64
sph_s64 = ctypes.c_int64
class struct_c__SA_Hasher(ctypes.Structure):
    pass

class union_c__SA_Hasher_0(ctypes.Union):
    pass

class struct_SHA3_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('hash', ctypes.c_uint64 * 25),
    ('message', ctypes.c_uint64 * 24),
    ('rest', ctypes.c_uint32),
    ('block_size', ctypes.c_uint32),
     ]

SHA3_CTX = struct_SHA3_CTX
class struct__SHA256_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('state', ctypes.c_uint32 * 8),
    ('bitcount', ctypes.c_uint64),
    ('buffer', ctypes.c_uint32 * 16),
     ]

SHA256_CTX = struct__SHA256_CTX
union_c__SA_Hasher_0._pack_ = True # source:False
union_c__SA_Hasher_0._fields_ = [
    ('sha2', SHA256_CTX),
    ('sha3', SHA3_CTX),
    ('blake', BLAKE256_CTX),
    ('groestl', GROESTL512_CTX),
    ('PADDING_0', ctypes.c_ubyte * 128),
]

struct_c__SA_Hasher._pack_ = True # source:False
struct_c__SA_Hasher._fields_ = [
    ('type', HasherType),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('ctx', union_c__SA_Hasher_0),
]

Hasher = struct_c__SA_Hasher
class struct__HMAC_SHA256_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('o_key_pad', ctypes.c_ubyte * 64),
    ('ctx', SHA256_CTX),
     ]

HMAC_SHA256_CTX = struct__HMAC_SHA256_CTX
class struct__HMAC_SHA512_CTX(ctypes.Structure):
    pass

class struct__SHA512_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('state', ctypes.c_uint64 * 8),
    ('bitcount', ctypes.c_uint64 * 2),
    ('buffer', ctypes.c_uint64 * 16),
     ]

SHA512_CTX = struct__SHA512_CTX
struct__HMAC_SHA512_CTX._pack_ = True # source:False
struct__HMAC_SHA512_CTX._fields_ = [
    ('o_key_pad', ctypes.c_ubyte * 128),
    ('ctx', SHA512_CTX),
]

HMAC_SHA512_CTX = struct__HMAC_SHA512_CTX
xmr_amount = ctypes.c_uint64
xmr_key64_t = ctypes.c_ubyte * 32 * 64
class struct_xmr_boro_sig(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('s0', ctypes.c_ubyte * 32 * 64),
    ('s1', ctypes.c_ubyte * 32 * 64),
    ('ee', ctypes.c_ubyte * 32),
     ]

xmr_boro_sig_t = struct_xmr_boro_sig
class struct_range_sig(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('asig', xmr_boro_sig_t),
    ('Ci', ctypes.c_ubyte * 32 * 64),
     ]

xmr_range_sig_t = struct_range_sig
xmr_h = struct_ge25519_t # Variable struct_ge25519_t
xmr_key_t = ctypes.c_ubyte * 32
class struct_xmr_ctkey(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('dest', ctypes.c_ubyte * 32),
    ('mask', ctypes.c_ubyte * 32),
     ]

xmr_ctkey_t = struct_xmr_ctkey
class struct_c__SA_nem_transaction_ctx(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('public_key', ctypes.c_ubyte * 32),
    ('buffer', POINTER_T(ctypes.c_ubyte)),
    ('offset', ctypes.c_uint64),
    ('size', ctypes.c_uint64),
     ]

nem_transaction_ctx = struct_c__SA_nem_transaction_ctx
nist256p1 = struct_c__SA_ecdsa_curve # Variable struct_c__SA_ecdsa_curve
nist256p1_info = struct_c__SA_curve_info # Variable struct_c__SA_curve_info
class struct__PBKDF2_HMAC_SHA256_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('odig', ctypes.c_uint32 * 8),
    ('idig', ctypes.c_uint32 * 8),
    ('f', ctypes.c_uint32 * 8),
    ('g', ctypes.c_uint32 * 16),
    ('first', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 3),
     ]

PBKDF2_HMAC_SHA256_CTX = struct__PBKDF2_HMAC_SHA256_CTX
class struct__PBKDF2_HMAC_SHA512_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('odig', ctypes.c_uint64 * 8),
    ('idig', ctypes.c_uint64 * 8),
    ('f', ctypes.c_uint64 * 8),
    ('g', ctypes.c_uint64 * 16),
    ('first', ctypes.c_char),
    ('PADDING_0', ctypes.c_ubyte * 7),
     ]

PBKDF2_HMAC_SHA512_CTX = struct__PBKDF2_HMAC_SHA512_CTX
class struct_c__SA_RC4_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('S', ctypes.c_ubyte * 256),
    ('i', ctypes.c_ubyte),
    ('j', ctypes.c_ubyte),
     ]

RC4_CTX = struct_c__SA_RC4_CTX
class struct_c__SA_rfc6979_state(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('v', ctypes.c_ubyte * 32),
    ('k', ctypes.c_ubyte * 32),
     ]

rfc6979_state = struct_c__SA_rfc6979_state
class struct__RIPEMD160_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('total', ctypes.c_uint32 * 2),
    ('state', ctypes.c_uint32 * 5),
    ('buffer', ctypes.c_ubyte * 64),
     ]

RIPEMD160_CTX = struct__RIPEMD160_CTX
secp256k1 = struct_c__SA_ecdsa_curve # Variable struct_c__SA_ecdsa_curve
secp256k1_info = struct_c__SA_curve_info # Variable struct_c__SA_curve_info
secp256k1_decred_info = struct_c__SA_curve_info # Variable struct_c__SA_curve_info
secp256k1_groestl_info = struct_c__SA_curve_info # Variable struct_c__SA_curve_info
class struct__SHA1_CTX(ctypes.Structure):
    _pack_ = True # source:False
    _fields_ = [
    ('state', ctypes.c_uint32 * 5),
    ('PADDING_0', ctypes.c_ubyte * 4),
    ('bitcount', ctypes.c_uint64),
    ('buffer', ctypes.c_uint32 * 16),
     ]

SHA1_CTX = struct__SHA1_CTX
sha256_initial_hash_value = [] # Variable ctypes.c_uint32 * 8
sha512_initial_hash_value = [] # Variable ctypes.c_uint64 * 8
__all__ = \
    ['wordlist', 'nist256p1', 'struct_c__SA_RC4_CTX',
    'struct_ge25519_p1p1_t', 'bignum25519', 'xmr_range_sig_t',
    'struct_c__SA_rfc6979_state', 'struct_range_sig',
    'xmr_boro_sig_t', 'union_c__UA_aes_inf', 'struct_c__SA_HDNode',
    'struct__SHA256_CTX', 'secp256k1', 'struct__RIPEMD160_CTX',
    'HASHER_GROESTLD_TRUNC', 'PBKDF2_HMAC_SHA512_CTX',
    'ed25519_signature', 'ge25519', 'nem_transaction_ctx',
    'BLAKE256_CTX', 'sph_u64', 'CURVE25519_NAME',
    'union_c__SA_sph_groestl_big_context_0', 'HASHER_SHA3',
    'HasherType', 'uint32_t', 'struct_ge25519_t',
    'struct_c__SA_sph_groestl_big_context', 'struct__SHA1_CTX',
    'uint64_t', 'secp256k1_info', 'struct_c__SA_Hasher',
    'struct_c__SA_ecdsa_curve', 'BLAKE2S_PERSONALBYTES', 't_rc',
    'sha256_initial_hash_value', 'struct___blake2b_state',
    'struct_c__SA_bignum256', 'int32_t', 'NIST256P1_NAME',
    'secp256k1_decred_info',
    'struct_c_groestlDOTh_S_groestlDOTh_2155', 'HASHER_BLAKED',
    'ge25519_niels', 'blake2b_state', 'union_c__SA_Hasher_0',
    'HMAC_SHA512_CTX', 'xmr_key_t', 'struct___blake2s_state',
    'ED25519_SHA3_NAME', 'size_t', 'BLAKE2B_SALTBYTES',
    'c__EA_HasherType', 'BLAKE2B_BLOCKBYTES',
    'struct_c__SA_nem_transaction_ctx', 'BLAKE2S_BLOCKBYTES',
    'BLAKE2S_OUTBYTES', 'struct__SHA512_CTX', 'sph_s32',
    'struct_SHA3_CTX', 'SECP256K1_GROESTL_NAME',
    'struct_c__SA_aes_encrypt_ctx', 'HASHER_SHA3K', 'blake2s_state',
    'BLAKE2B_KEYBYTES', 'struct__HMAC_SHA256_CTX',
    'struct_ge25519_niels_t', 'SHA512_CTX', 'RC4_CTX',
    'RIPEMD160_CTX', 'struct_c__SA_BLAKE256_CTX', 'ED25519_NAME',
    'SECP256K1_DECRED_NAME', 'HASHER_SHA2D', 'hash_512bits',
    'struct_xmr_boro_sig', 'aes_encrypt_ctx', 'sph_u32',
    'struct__PBKDF2_HMAC_SHA512_CTX', 'ed25519_secret_key',
    'PBKDF2_HMAC_SHA256_CTX', 'HASHER_BLAKE',
    'struct_c__SA_curve_info', 'struct_c__SA_curve_point',
    'BLAKE2S_SALTBYTES', 'bignum256', 'xmr_ctkey_t', 'SHA3_CTX',
    'struct_c__SA_aes_decrypt_ctx', 'aes_decrypt_ctx',
    'HMAC_SHA256_CTX', 'BASE32_ALPHABET_RFC4648', 'bignum256modm',
    'uint8_t', 'BLAKE2S_KEYBYTES', 'cbuf_inc', 'GROESTL512_CTX',
    'struct_ge25519_pniels_t', 'sph_s64', 'secp256k1_groestl_info',
    'rfc6979_state', 'BLAKE2B_OUTBYTES', 'xmr_key64_t', 'curve_info',
    'nist256p1_info', 'struct__PBKDF2_HMAC_SHA256_CTX',
    'struct__HMAC_SHA512_CTX', 'SECP256K1_NAME', 'xmr_amount',
    'HDNode', 'blake2s_constant', 'sha512_initial_hash_value',
    'ED25519_KECCAK_NAME', 'blake2b_constant', 'ecdsa_curve', 'xmr_h',
    'SHA256_CTX', 'ge25519_pniels', 'curve_point', 'Hasher',
    'struct_xmr_ctkey', 'SHA1_CTX', 'HASHER_SHA2', 'aes_inf',
    'ed25519_public_key', 'BLAKE2B_PERSONALBYTES', 'ge25519_p1p1',
    'sph_groestl_big_context', 'POINTER_T']

