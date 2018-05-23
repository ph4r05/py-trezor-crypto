#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05

# See CFFI docs at https://cffi.readthedocs.org/en/latest/
# Inspiration:
#  https://github.com/pyca/pynacl/blob/master/setup.py
#  https://github.com/jiffyclub/cext23/tree/master/cext23/cffi

from cffi import FFI
import subprocess
import errno
import glob
import os
import re
import sys
import tempfile
import argparse
import pkg_resources
import logging
import importlib
import itertools
import collections
from pycparser import c_parser, c_ast, c_generator


#
# ctypes:
#   - pip install ctypeslib2
#   - copy libcland.dylib to the current directory
#
# ./venv/bin/clang2py --clang-args='-Isrc/ -DUSE_KECCAK=1 -DUSE_MONERO=1 -I/Library/Developer/CommandLineTools/usr/lib/clang/9.1.0/include' src/monero/*.h
#


logger = logging.getLogger(__name__)
ffi = FFI()


INT_TYPES = [
    'uint16_t', 'uint32_t', 'uint64_t',
    'int16_t', 'int32_t', 'int64_t',
    'int', 'long', 'size_t', 'ssize_t',
    'char', 'bool', 'boolean',
]


class FuncCodeGenPar(object):
    def __init__(self, name, opars=None, out_inits=None, out_rets=None, ret_ov=None, no_ct=False, no_ctr=False):
        self.name = name
        self.opars = opars  # output parameters
        self.out_inits = out_inits  # output params initialization
        self.out_rets = out_rets  # output params return transformation
        self.ret_ov = ret_ov  # return value override
        self.no_ct = no_ct
        self.no_ctr = no_ctr

    def get_out_init(self, idx):
        return self.out_inits[idx] if self.out_inits and idx in self.out_inits else None



FUNCS_PARAMS = [
    FuncCodeGenPar('random_buffer'),
    FuncCodeGenPar('get256_modm', no_ctr=True),
    FuncCodeGenPar('expand256_modm', no_ct=True, no_ctr=True),
    FuncCodeGenPar('ge25519_unpack_vartime', no_ctr=True),
    FuncCodeGenPar('xmr_fast_hash', no_ctr=True),
    FuncCodeGenPar('xmr_hasher_update', [], no_ct=True, no_ctr=True),
    FuncCodeGenPar('xmr_hasher_final', [1], out_inits={1: 'tt.KEY_BUFF()'}, ret_ov='bytes(hash)'),
    FuncCodeGenPar('xmr_hash_to_scalar', no_ct=True, no_ctr=True),
    FuncCodeGenPar('xmr_hash_to_ec', no_ct=True, no_ctr=True),
    FuncCodeGenPar('groestl512_Init'),
    FuncCodeGenPar('groestl512_Update'),
    FuncCodeGenPar('groestl512_Final'),
]


def get_compile_args():
    return [
        '--std=c99',
        '-fPIC',
        '-DUSE_MONERO=1',
        '-DUSE_KECCAK=1',
        '-DUSE_LIBSODIUM',
        '-DSODIUM_STATIC=1',
        '-DRAND_PLATFORM_INDEPENDENT=1',
    ]


def get_blacklisted_funcs():
    return [
        'ge25519_scalarmult_base_choose_niels',
        'ge25519_scalarmult_base_niels'
    ]


def get_functions_out_params():
    return {x.name: x.opars for x in FUNCS_PARAMS if x.opars is not None}


def get_function_codegen_params():
    return collections.defaultdict(lambda: None, {x.name: x for x in FUNCS_PARAMS})


def get_main_header():
    # root header file to process - including all components for the module
    tpl = '''
#include <rand.h>
#include <hasher.h>
#include <hmac.h>
#include <pbkdf2.h>
#include <bignum.h>
#include <base32.h>
#include <base58.h>
#include <monero/monero.h>
            '''
    return tpl


def replace_sizeofs(to_parse):
    to_parse = re.sub(r'\bsizeof\(uint8_t\)', '1', to_parse)
    to_parse = re.sub(r'\bsizeof\(uint16_t\)', '2', to_parse)
    to_parse = re.sub(r'\bsizeof\(uint32_t\)', '4', to_parse)
    to_parse = re.sub(r'\bsizeof\(uint64_t\)', '8', to_parse)
    return to_parse


def rel_setup(path):
    return os.path.relpath(path, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def get_basedir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '../src'))


def get_fake_libs():
    return os.path.abspath(os.path.join(os.path.dirname(__file__),
                                        '../tools/pycparser/utils/fake_libc_include'))


def get_package_file_path(name):
    name = [name] if not isinstance(name, list) else name
    try:
        cffi_h = pkg_resources.resource_filename(__name__, os.path.join(*name))
    except:
        cffi_h = os.path.abspath(os.path.join(*([os.path.dirname(__file__)] + name)))
    return cffi_h


def get_cffi_h_fname():
    return get_package_file_path(['..', 'data', 'cffi.h'])


def get_ctypes_tpl_fname():
    return get_package_file_path(['..', 'data', 'trezor_ctypes_tpl.py'])


def get_ctypes_types_fname():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), 'trezor_ctypes_gen.py'))


def get_ctypes_fnc_fname():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), 'trezor_cfunc_gen.py'))


def only_files(headers, allowed):
    nheaders = []
    for h in headers:
        is_ok = False
        for allw in allowed:
            if h.endswith(allw):
                is_ok = True
                break
        if is_ok:
            nheaders.append(h)
    return nheaders


def remove_files(files, blacklist):
    nheaders = []
    for h in files:
        is_ok = True
        for blck in blacklist:
            if h.endswith(blck):
                is_ok = False
                break
        if is_ok:
            nheaders.append(h)
    return nheaders


def pkg_config(args):
    p, t = None, None

    try:
        p = subprocess.Popen(['pkg-config'] + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
    else:
        t = p.stdout.read().strip()
    if p.wait() == 0 and t:
        return t

    return None


def libsodium_flags():
    cflags = os.getenv('LIBSODIUM_CFLAGS', '')
    ldflags = os.getenv('LIBSODIUM_LDLAGS', '-lsodium')
    if cflags is None:
        cflags = pkg_config(['--cflags', 'libsodium']).decode('utf8').split(' ')
    else:
        cflags = cflags.split(' ')

    if ldflags is None:
        ldflags = pkg_config(['--libs', 'libsodium']).decode('utf8').split(' ')
    else:
        ldflags = ldflags.split(' ')

    return [x for x in cflags if x], [x for x in ldflags if x]


def get_compiler():
    return os.getenv('CC', 'gcc')


def detect_compiler():
    en = os.getenv('CC', None)
    if en is not None:
        return en

    guesses = ['gcc', 'clang']
    for g in guesses:
        try:
            p = subprocess.Popen([g, '-v'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as e:
            if e.errno != errno.ENOENT:
                continue
        else:
            if p.wait() == 0:
                return g
    raise ValueError('Compiler could not be detected')


def preprocess(headers, compiler=None, use_fake_libs=True):
    """
    Runs preprocessor on the headers
    :param headers:
    :param compiler: compiler executable, otherwise autodetected (CC env / gcc / clang)
    :param use_fake_libs: use pycparser fake libs for easier parsing
    :return:
    """
    p, t = None, None
    if compiler is None:
        compiler = detect_compiler()

    fake_libs = 'src'
    if use_fake_libs:
        fake_libs = get_fake_libs()

    args = ['-nostdinc',
            '-E',
            '-D__attribute__(x)=',
            '-I%s' % fake_libs,
            '-Isrc/',
            ] + get_compile_args()

    try:
        p = subprocess.Popen([compiler] + args + headers, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
    if p.wait() != 0:
        err = p.stderr.read().strip()
        print(err.decode('utf8'))
        raise EnvironmentError('Preprocessor error')

    t = p.stdout.read().strip()
    return t


def filter_headers(headers, base_dir):
    """
    Processes header file produced by the preprocessor and keeps only records coming from
    the original project (i.e., skipping standard definitions from compiler include folders,
    e.g., uint8, ...)

    :param headers:
    :param base_dir:
    :return:
    """
    lns = headers.split(b'\n')
    base_dir = bytes(base_dir, 'utf8')
    hstack = []
    headers_done = False
    skip_block = False
    last_block = None

    for idx, line in enumerate(lns):
        m = re.match(b'^# [\d]+ "(.+?)".*$', line)
        if m is None:
            if not headers_done:
                headers_done = True
                skip_block = last_block is None or not last_block.startswith(base_dir)

            if skip_block:
                continue

            hstack.append(line)

        else:
            if headers_done:
                skip_block = False
                headers_done = False
            elif skip_block:
                continue

            pth = m.group(1)
            built_in = pth.startswith(b'<')
            last_block = None

            if built_in:
                continue

            abspath = os.path.abspath(pth)
            last_block = abspath

    return b'\n'.join(hstack)


def is_simple_num_ast(ast):
    """
    The given declaration (parameter / return value) is simple int type
    :return:
    """
    if isinstance(ast, c_ast.Decl):
        return is_simple_num_ast(ast.type)
    if isinstance(ast, c_ast.Typename):
        return is_simple_num_ast(ast.type)
    if isinstance(ast, (c_ast.PtrDecl, c_ast.ArrayDecl)):
        return False
    if not isinstance(ast, c_ast.TypeDecl):
        raise ValueError('Ctype conversion error: %s' % ast)

    tt = ast.type
    if not isinstance(tt, c_ast.IdentifierType):
        raise ValueError('Ctype conversion error2: %s' % tt)

    ty = tt.names[0]
    if len(tt.names) == 2 and (tt.names[0] in ['signed', 'unsigned']):
        ty = tt.names[1]

    return ty in INT_TYPES


def is_byte_array(ast):
    """
    pointer to char/uchar/int8/uint8 or array of these types
    :param ast:
    :return:
    """
    def is_barr_int(ast, arr_det=False):
        if isinstance(ast, c_ast.Decl):
            return is_barr_int(ast.type)
        if isinstance(ast, c_ast.Typename):
            return is_barr_int(ast.type)
        if isinstance(ast, (c_ast.PtrDecl, c_ast.ArrayDecl)):
            return (is_barr_int(ast.type, True) if not arr_det else False)  # only 1D array allowed
        if not isinstance(ast, c_ast.TypeDecl):
            raise ValueError('Ctype conversion error: %s' % ast)

        tt = ast.type
        if not isinstance(tt, c_ast.IdentifierType):
            raise ValueError('Ctype conversion error2: %s' % tt)

        ty = tt.names[0]
        if len(tt.names) == 2 and (tt.names[0] in ['signed', 'unsigned']):
            ty = tt.names[1]

        return arr_det and ty in ['char', 'int', 'uint8_t', 'int8_t']
    return is_barr_int(ast)


def eval_ast(node):
    if isinstance(node, c_ast.BinaryOp):
        if node.op == '/':
            return eval_ast(node.left) // eval_ast(node.right)
        elif node.op == '+':
            return eval_ast(node.left) + eval_ast(node.right)
        elif node.op == '-':
            return eval_ast(node.left) - eval_ast(node.right)
        elif node.op == '*':
            return eval_ast(node.left) * eval_ast(node.right)
        else:
            raise ValueError('Unknown op: %s' % node.op)
    elif isinstance(node, c_ast.Constant):
        return int(node.value)
    else:
        raise ValueError('Unknown node: %s' % node)


class ArrayEval(c_ast.NodeVisitor):
    def visit_ArrayDecl(self, node):
        dim_val = eval_ast(node.dim)
        node.dim = c_ast.Constant('int', '%s' % dim_val)


def coord_path(coord):
    if coord is None or coord.file is None or coord.file.startswith('<'):
        return None
    return os.path.abspath(coord.file)


def remove_defs(headers, base_dir, blacklist, take_typedefs=True, take_funcs=True, take_decls=True, **kwargs):
    """
    Keeps only type definitions and function declarations.
    :param headers:
    :param base_dir:
    :param blacklist:
    :return:
    """
    parser = c_parser.CParser()

    def take_coord(coord):
        pth = coord_path(coord)
        return pth is not None and pth.startswith(base_dir)

    class FuncDefVisitor(c_ast.NodeVisitor):
        def __init__(self):
            self.defs = []
            self.ar = ArrayEval()

        def visit_FuncDef(self, node):
            return

        def visit_Typedef(self, node):
            if not take_coord(node.coord) or node.name in blacklist or not take_typedefs: return
            self.ar.visit(node)
            self.defs.append(node)

        def visit_FunDecl(self, node):
            if not take_coord(node.coord) or node.decl.name in blacklist or not take_funcs: return
            self.ar.visit(node)
            self.defs.append(node)

        def visit_Decl(self, node):
            if not take_coord(node.coord) or node.name in blacklist or not take_decls: return
            if 'static' in node.storage: return
            self.ar.visit(node)
            self.defs.append(node)

    to_parse = headers.decode('utf8')

    # quick hack for sizeof
    to_parse = replace_sizeofs(to_parse)

    ast = parser.parse(to_parse, debuglevel=0)

    v = FuncDefVisitor()
    v.visit(ast)
    nast = c_ast.FileAST(v.defs)

    generator = c_generator.CGenerator()
    genc = generator.visit(nast)

    return genc


def generate_cffi_header(base_dir, tpl, debug=False, **kwargs):
    tmp_hdr = tempfile.NamedTemporaryFile(prefix='tcry_root_', suffix='.h', delete=False)
    with tmp_hdr:
        tmp_hdr.write(tpl.encode('utf8'))

    headers = [tmp_hdr.name]
    parsed = preprocess(headers)
    parsed2 = filter_headers(parsed, base_dir)

    if debug:
        with open('/tmp/prepro.h', 'wb') as fh:
            fh.write(parsed)
        with open('/tmp/prepro2.h', 'wb') as fh:
            fh.write(parsed2)

    parsed2 = remove_defs(parsed, base_dir, get_blacklisted_funcs())

    if debug:
        with open('/tmp/prepro3.h', 'w') as fh:
            fh.write(parsed2)

    return parsed2, tmp_hdr


def load_h_cffi(base_dir=None, tpl=None, refresh=False, cffi_h=None, debug=False, **kwargs):
    if tpl is None:
        tpl = get_main_header()
    if base_dir is None:
        base_dir = get_basedir()

    tmp_hdr = None
    cffi_hdat = None
    if cffi_h is None:
        cffi_h = get_cffi_h_fname()

    if os.path.exists(cffi_h) and not refresh:
        logger.debug('Using existing CFFI header file')
        with open(cffi_h) as fh:
            cffi_hdat = fh.read().strip()

    if not cffi_hdat or len(cffi_hdat) == 0:
        logger.info('CFFI header file not found, generating from sources')
        cffi_hdat, tmp_hdr = generate_cffi_header(base_dir, tpl, debug)
        logger.info('CFFI generated: %s' % tmp_hdr.name)

        try:
            with open(cffi_h, 'w+') as fh:
                fh.write(cffi_hdat)
        except Exception as e:
            logger.warning(e)

        if debug:
            with open('/tmp/prepro3.h', 'w') as fh:
                fh.write(cffi_hdat)

    if not debug and tmp_hdr:
        os.unlink(tmp_hdr.name)

    return cffi_hdat, (tmp_hdr.name if tmp_hdr else None), cffi_h


def main_cffi():
    debug = int(os.getenv('TCRY_CFFI_DEBUG', 0))
    sodium_flags = libsodium_flags()

    base_dir = get_basedir()

    c_files = glob.glob(os.path.join(base_dir, "*.c")) \
              + glob.glob(os.path.join(os.path.join(base_dir, 'aes'), "*.c")) \
              + glob.glob(os.path.join(os.path.join(base_dir, 'ed25519-donna'), "*.c"))\
              + glob.glob(os.path.join(os.path.join(base_dir, 'monero'), "*.c"))

    c_files = remove_files(c_files, ['rfc6979.c'])
    c_files = [rel_setup(x) for x in c_files]

    # root header file to process - including all components for the module
    tpl = get_main_header()
    cffi_hdat, tmp_hdr = load_h_cffi(base_dir=base_dir, tpl=tpl, debug=debug)[:2]

    # set_source is where you specify all the include statements necessary
    # for your code to work and also where you specify additional code you
    # want compiled up with your extension, e.g. custom C code you've written
    #
    # set_source takes mostly the same arguments as distutils' Extension, see:
    # https://cffi.readthedocs.org/en/latest/cdef.html#ffi-set-source-preparing-out-of-line-modules
    # https://docs.python.org/3/distutils/apiref.html#distutils.core.Extension
    ffi.set_source(
        'trezor_crypto.tcry_cffi',
        tpl,
        include_dirs=['src/'],
        sources=c_files,
        extra_compile_args=get_compile_args() + [
            '-I.',
            '-I%s' % base_dir
            ] + sodium_flags[0],
        extra_link_args=[] + sodium_flags[1])

    # https://cffi.readthedocs.org/en/latest/cdef.html#ffi-cdef-declaring-types-and-functions
    ffi.cdef(cffi_hdat)


class ArgData(object):
    """
    Variable declaration / parameter / return type
    """
    def __init__(self, ct, pt_type=0, is_const=False, name=None, ast=None, sub_ct=None, arr_dim=None, sub_res=None, *args, **kwargs):
        self.ct = ct
        self.pt_type = pt_type  # 1 = pointer, 2 = array
        self.is_const = is_const
        self.name = name
        self.ast = ast
        self.sub_type = sub_ct
        self.sub_res = sub_res
        self.is_byval = is_simple_num_ast(ast) if ast else None
        self.is_int = self.is_byval
        self.is_bytes = is_byte_array(ast) if ast else None
        self.arr_dim = arr_dim

    def is_void(self):
        return self.ct is None

    def is_const_or_byval(self):
        return self.is_byval or self.is_const

    def pt_def(self):
        return self.sub_type if self.sub_type else self.ct


class AstToCtype(object):
    def __init__(self, defined_types):
        self.defined_types = set(defined_types)

    def is_byval(self, ast):
        """
        Passed by value / cannot modify
        :return:
        """
        return is_simple_num_ast(ast)

    def ast_to_ctype(self, ast):
        """
        Translates AST type to the ctype
        :param ast:
        :return:
        """
        if isinstance(ast, c_ast.Decl):
            return self.ast_to_ctype(ast.type)
        if isinstance(ast, c_ast.Typename):
            return self.ast_to_ctype(ast.type)

        is_ptr = isinstance(ast, c_ast.PtrDecl)
        is_arr = isinstance(ast, c_ast.ArrayDecl)
        if is_arr:
            r = self.ast_to_ctype(ast.type)
            tp = '%s * %s' % (r.ct, eval_ast(ast.dim))
            return ArgData(tp, 2, r.is_const, r.name, ast=ast, sub_ct=tp, arr_dim=eval_ast(ast.dim), sub_res=r)

        if is_ptr:
            r = self.ast_to_ctype(ast.type)
            if r.is_void():
                return ArgData('ct.c_void_p', 1, r.is_const, r.name, ast=ast)
            return ArgData('tt.POINTER(%s)' % r.ct, 1, r.is_const, r.name, ast=ast, sub_ct=r.ct)

        if not isinstance(ast, c_ast.TypeDecl):
            raise ValueError('Ctype conversion error: %s' % ast)

        tt = ast.type
        if not isinstance(tt, c_ast.IdentifierType):
            raise ValueError('Ctype conversion error2: %s' % tt)

        unsigned = ''
        is_const = 'const' in ast.quals
        ttnames = tt.names
        if ttnames[0] == 'signed':
            ttnames.pop(0)
        if ttnames[0] == 'unsigned':
            ttnames.pop(0)
            unsigned = 'u'
            if len(ttnames) == 0:
                ttnames.append('int')

        if ttnames == ['char']:
            return ArgData('ct.c_%sbyte' % unsigned, 0, is_const, fix_arg_name(ast.declname), ast=ast)
        elif len(ttnames) == 1 and (ttnames[0] in self.defined_types or ttnames[0].endswith('CTX')):
            return ArgData('tt.%s' % ttnames[0], 0, is_const, fix_arg_name(ast.declname), ast=ast)
        elif ttnames == ['void']:
            return ArgData(None, 0, is_const, fix_arg_name(ast.declname), ast=ast)
        else:
            return ArgData('ct.c_%s%s' % (unsigned, ttnames[0]), 0, is_const, fix_arg_name(ast.declname), ast=ast)
            # raise ValueError('Unknown vale: %s' % tt.names)


def fix_arg_name(name):
    """
    Fix arg name / reserved word?
    :param name:
    :return:
    """
    if name in ['pass', 'break', 'continue', 'except', 'try', 'for', 'while', 'do', 'def', 'class', 'in',
                'isinstance', 'tuple', 'list', 'set', 'None']:
        return '%s_' % name
    return name


def get_output_args(ast, args, ret_type, lut):
    """
    Determines indices of output arguments
    :param ast:
    :param args:
    :param consts:
    :return:
    """
    if lut and ast.name in lut:
        logger.debug('Using lut out params for %s' % ast.name)
        return lut[ast.name]

    if len(args) == 0:
        return []

    first_grp = None
    last_grp = None
    num_grp = 0
    consts = [x.is_const_or_byval() for x in args]
    for idx, (k, g) in enumerate(itertools.groupby(enumerate(consts), key=lambda y: y[1])):
        first_grp = (k, list(g)) if first_grp is None else first_grp
        last_grp = (k, list(g))
        num_grp += 1

    if num_grp > 2 and first_grp[0] == last_grp[0]:
        logger.warning('Problem with output guess for %s' % ast.name)
    if first_grp[0] and last_grp[0]:
        return []
    if not first_grp[0]:
        return [x[0] for x in first_grp[1]]
    elif not last_grp[0]:
        return [x[0] for x in last_grp[1]]
    else:
        return []


def arg_name(arg, idx):
    arg_names = ['r', 'a', 'b', 'c', 'd', 'e', 'f', 'h']
    return arg.name if arg.name else arg_names[idx]


def arg_call_form(arg, name):
    # TODO: bytes() wrapper, int wrapper?
    if arg.pt_type == 1 and not arg.is_bytes:
        return 'ct.byref(%s)' % (name if name else arg.name)
    else:
        return name


def arg_return(arg, name=None):
    if arg.is_bytes:
        return 'bytes(%s)' % (name if name else arg.name)
    elif arg.is_int:
        return 'int(%s)' % (name if name else arg.name)
    else:
        return name if name else arg.name


def arg_call_list(args, arg_str):
    res = []
    for idx, c in enumerate(args):
        if c.is_void():
            continue
        res.append(arg_call_form(c, arg_str[idx]))
    return res


def ctypes_functions():
    base_dir = get_basedir()
    blacklist = get_blacklisted_funcs()
    parser = c_parser.CParser()
    out_params_out = get_functions_out_params()

    # Load generated types map
    types_fname = get_ctypes_types_fname()
    _path_backup = sys.path
    sys.path.insert(0, os.path.dirname(types_fname))
    types_mod_name = os.path.splitext(os.path.basename(types_fname))[0]
    types_mod = __import__(types_mod_name)
    sys.path = _path_backup
    defined_types = types_mod.__all__

    tmp_hdr = tempfile.NamedTemporaryFile(prefix='tcry_ctypes_', suffix='.h', delete=False)
    with tmp_hdr:
        tmp_hdr.write(get_main_header().encode('utf8'))

    headers = [tmp_hdr.name]
    to_parse = preprocess(headers).decode('utf8')

    def take_coord(coord):
        pth = coord_path(coord)
        return pth is not None and pth.startswith(base_dir)

    class FuncDefVisitor(c_ast.NodeVisitor):
        def __init__(self):
            self.defs_clib = []
            self.defs_fnc = []
            self.ar = ArrayEval()
            self.ctyper = AstToCtype(defined_types)
            self.code_pars = get_function_codegen_params()

        def visit_Decl(self, node):
            if not take_coord(node.coord) or node.name in blacklist: return
            if not isinstance(node.type, c_ast.FuncDecl): return
            if 'static' in node.storage: return

            # node.show()
            # Argument list, return value processing

            ast_args = node.type.args.params
            n_args = len(ast_args)
            args = []
            for n in ast_args:
                arg = self.ctyper.ast_to_ctype(n)
                if arg.is_void() and n_args == 1:
                    break
                args.append(arg)

            ret_type = self.ctyper.ast_to_ctype(node.type.type)
            ret_type.name = '_res'
            ret_nonvoid = not ret_type.is_void()
            out_args = get_output_args(node, args, ret_type, lut=out_params_out)
            code_pars = self.code_pars[node.name]  # type: FuncCodeGenPar

            # Ctype code gen
            arg_list = ', '.join([x.ct for x in args if x and not x.is_void()])
            cdef = 'CLIB.%s.argtypes = [%s]' % (node.name, arg_list)
            self.defs_clib.append(cdef)
            if ret_nonvoid:
                cdef = 'CLIB.%s.restype = %s' % (node.name, ret_type.ct)
                self.defs_clib.append(cdef)

            arg_str = [arg_name(x, idx) for idx, x in enumerate(args) if not x.is_void()]
            arg_par = arg_call_list(args, arg_str)

            fnc_call = 'CLIB.%s(%s)' % (node.name, ', '.join(arg_par))
            tpl = 'def %s(%s): \n' % (node.name, ', '.join(arg_str))
            tpl += '    %s%s\n' % ('return ' if ret_nonvoid else '', arg_return(ret_type, fnc_call))
            tpl += '\n'
            if code_pars is None or not code_pars.no_ct:
                self.defs_fnc.append(tpl)

            if len(out_args) == 0:
                return

            arg_str_n = [arg_name(x, idx) for idx, x in enumerate(args) if not x.is_void() and idx not in out_args] if args else []
            arg_ret = [arg_name(x, idx) for idx, x in enumerate(args) if not x.is_void() and idx in out_args] if args else []

            arg_ret = [arg_return(args[idx], x) for idx, x in enumerate(arg_ret)]
            ret_list = ([arg_return(ret_type)] if ret_nonvoid else []) + arg_ret

            tpl = 'def %s_r(%s): \n' % (node.name, ', '.join(arg_str_n))
            for idx in out_args:
                oinit = code_pars.get_out_init(idx) if code_pars else None
                if oinit:
                    tpl += '    %s = %s\n' % (arg_str[idx], oinit)
                else:
                    tpl += '    %s = (%s)()\n' % (arg_str[idx], args[idx].pt_def())

            tpl += '    %sCLIB.%s(%s)\n' % ('_res = ' if ret_nonvoid else '', node.name, ', '.join(arg_par))
            if code_pars and code_pars.ret_ov:
                tpl += '    return %s' % code_pars.ret_ov
            else:
                tpl += '    return %s\n' % (', '.join(ret_list))
            tpl += '\n'
            if code_pars is None or not code_pars.no_ctr:
                self.defs_fnc.append(tpl)

    # quick hack for sizeof
    to_parse = replace_sizeofs(to_parse)
    ast = parser.parse(to_parse, debuglevel=0)

    v = FuncDefVisitor()
    v.visit(ast)

    with open(get_ctypes_tpl_fname()) as fh:
        tpl_data = fh.read()

    fname = get_ctypes_fnc_fname()
    with open(fname, 'w') as fh:
        setup_defs = ['    %s' % x for x in v.defs_clib]
        tpl_data = re.sub(r'^[^\n]*# {{ SETUP_LIB }}[^\n]*$', '\n'.join(setup_defs), tpl_data, flags=re.MULTILINE)
        tpl_data = re.sub(r'^[^\n]*# {{ WRAPPERS }}[^\n]*$', '\n'.join(v.defs_fnc), tpl_data, flags=re.MULTILINE)
        fh.write(tpl_data)

    return


def ctypes_gen(includes=None, use_fake_libs=False, debug=False):
    """
    Generates ctypes types for trezor_crypto
    :return:
    """
    from ctypeslib import clang2py
    from pipes import quote

    if includes is None:
        includes = []

    types_fname = get_ctypes_types_fname()
    clang_args = get_compile_args() + [
        '-Isrc/'
    ]

    for inc in includes:
        clang_args.append('-I%s' % quote(inc))
    if includes is None and os.path.exists('/usr/include'):
        clang_args.append('-I%s' % quote('/usr/include'))
    # detect default includes: gcc -xc -E -v /dev/null

    base_dir = 'src'
    h_files = glob.glob(os.path.join(base_dir, "*.h")) \
               + ['src/ed25519-donna/ed25519-donna.h', ] \
               + glob.glob(os.path.join(os.path.join(base_dir, 'aes'), "*.h")) \
               + glob.glob(os.path.join(os.path.join(base_dir, 'monero'), "*.h"))

    args = [
        'clang2py',
        '--clang-args=%s' % quote(' '.join(clang_args)),
        '-o%s' % quote(types_fname),
    ]
    for cf in h_files:
        args.append(quote(cf))

    logger.info('Clang args: %s' % (' '.join(args)))

    _back = sys.argv
    sys.argv = args
    clang2py.main()
    sys.argv = _back

    # post edit
    with open(types_fname) as fh:
        types_data = fh.read()

    types_data = re.sub(r'\]\s*$', ', \'POINTER_T\']\n\n', types_data)
    with open(types_fname, 'w') as fh:
        fh.write(types_data)

    ctypes_functions()


def main():
    parser = argparse.ArgumentParser(description='Trezor-crypto python binding')
    parser.add_argument('-a', '--action', action='store', choices=['cffi_h', 'ctypes'],
                        help='Actions')

    parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                        help='Debug')

    parser.add_argument('--fake-libs', dest='fake_libs', default=False, action='store_const', const=True,
                        help='Use fake libs for stddef/stdint')

    parser.add_argument('-I', dest='inc', default=[], nargs=argparse.ZERO_OR_MORE,
                        help='Include directories')

    args = parser.parse_args()
    if args.action == 'cffi_h':
        _, tmp, cffi_h = load_h_cffi(refresh=True, debug=args.debug)
        print('CFFI header regenerated: %s, source: %s' % (cffi_h, tmp))

    elif args.action == 'ctypes':
        ctypes_gen(includes=args.inc, use_fake_libs=args.fake_libs, debug=args.debug)


if __name__ == "__cffi__":
    main_cffi()

elif __name__ == '__main__':
    main()

