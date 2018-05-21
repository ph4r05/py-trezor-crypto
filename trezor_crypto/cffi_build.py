# See CFFI docs at https://cffi.readthedocs.org/en/latest/
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


def get_basedir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '../src'))


def get_fake_libs():
    return os.path.abspath(os.path.join(os.path.dirname(__file__),
                                        '../tools/pycparser/utils/fake_libc_include'))


def get_cffi_h_fname():
    try:
        cffi_h = pkg_resources.resource_filename(__name__, os.path.join('..', 'data', 'cffi.h'))
    except:
        cffi_h = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'data', 'cffi.h'))
    return cffi_h


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

    return cflags, ldflags


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

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../src'))

    c_files = glob.glob(os.path.join(base_dir, "*.c")) \
              + glob.glob(os.path.join(os.path.join(base_dir, 'aes'), "*.c")) \
              + glob.glob(os.path.join(os.path.join(base_dir, 'ed25519-donna'), "*.c"))\
              + glob.glob(os.path.join(os.path.join(base_dir, 'monero'), "*.c"))

    c_files = remove_files(c_files, ['rfc6979.c'])

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


def is_const(ast):
    pass


def ast_to_ctype(ast):
    """
    Translates AST type to the ctype
    :param ast:
    :return:
    """
    CUST_TYPES = ['ge25519', 'ge25519_niels', 'ge25519_pniels', 'ge25519_p1p1', 'bignum256modm', 'bignum25519',
                  'SHA1_CTX', 'SHA3_CTX', 'SHA512_CTX', 'SHA256_CTX', 'xmr_boro_sig_t']
    if isinstance(ast, c_ast.Decl):
        return ast_to_ctype(ast.type)
    if isinstance(ast, c_ast.Typename):
        return ast_to_ctype(ast.type)

    is_ptr = isinstance(ast, c_ast.PtrDecl)
    is_arr = isinstance(ast, c_ast.ArrayDecl)
    if is_arr:
        r = ast_to_ctype(ast.type)
        return '%s * %s' % (r[0], eval_ast(ast.dim)), 1, r[2], r[3]

    if is_ptr:
        r = ast_to_ctype(ast.type)
        if r[0] is None:
            return 'ctypes.c_void_p', 1, r[2], r[3]
        return 'POINTER(%s)' % r[0], 1, r[2], r[3]

    if not isinstance(ast, c_ast.TypeDecl):
        raise ValueError('Ctype conversion error: %s' % ast)

    tt = ast.type
    if not isinstance(tt, c_ast.IdentifierType):
        raise ValueError('Ctype conversion error2: %s' % tt)

    is_const = 'const' in ast.quals
    if tt.names == ['unsigned', 'char']:
        return 'ctypes.c_ubyte', 0, is_const, ast.declname
    elif len(tt.names) == 1 and (tt.names[0] in CUST_TYPES or tt.names[0].endswith('CTX')):
        return 'tt.%s' % tt.names[0], 0, is_const, ast.declname
    elif tt.names == ['void']:
        return None, 0, is_const, ast.declname
    else:
        return ('ctypes.c_%s' % tt.names[0]), 0, is_const, ast.declname
        # raise ValueError('Unknown vale: %s' % tt.names)


def ctypes_functions():
    base_dir = get_basedir()
    blacklist = get_blacklisted_funcs()
    parser = c_parser.CParser()

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
            self.defs = []
            self.ar = ArrayEval()

        def visit_Decl(self, node):
            if not take_coord(node.coord) or node.name in blacklist: return
            if not isinstance(node.type, c_ast.FuncDecl): return
            if 'static' in node.storage: return

            # node.show()
            # print(type(node), node.name, node.quals, node.type, node.storage, node.funcspec)
            args = []
            for n in node.type.args.params:
                args.append(ast_to_ctype(n))
            # print(args)

            arg_list = ', '.join([x[0] for x in args if x and x[0]])
            ret_type = ast_to_ctype(node.type.type)
            print('CLIB.%s.argtypes = [%s]' % (node.name, arg_list))
            if ret_type and ret_type[0]:
                print('CLIB.%s.restype = %s' % (node.name, ret_type[0]))



            self.ar.visit(node)
            self.defs.append(node)

    # quick hack for sizeof
    to_parse = replace_sizeofs(to_parse)

    ast = parser.parse(to_parse, debuglevel=0)

    v = FuncDefVisitor()
    v.visit(ast)
    nast = c_ast.FileAST(v.defs)

    generator = c_generator.CGenerator()
    genc = generator.visit(nast)

    return genc


def ctypes_gen(includes=None, use_fake_libs=False, debug=False):
    """
    Generates ctypes types for trezor_crypto
    :return:
    """
    from ctypeslib import clang2py
    from pipes import quote

    if includes is None:
        includes = []

    types_fname = os.path.abspath(os.path.join(os.path.dirname(__file__), 'trezor_ctypes.py'))
    func_fname = os.path.abspath(os.path.join(os.path.dirname(__file__), 'trezor_cfunc.py'))

    clang_args = get_compile_args() + [
        '-Isrc/'
    ]

    for inc in includes:
        clang_args.append('-I%s' % quote(inc))
    if includes is None and os.path.exists('/usr/include'):
        clang_args.append('-I%s' % quote('/usr/include'))
    # detect default includes: gcc -xc -E -v /dev/null

    base_dir = 'src'
    # ['src/hasher.h',
    #            'src/rand.h',
    #            'src/sha2.h',
    #            'src/sha3.h',
    #            'src/ed25519-donna/ed25519-donna.h',
    #            ]\

    h_files = glob.glob(os.path.join(base_dir, "*.h")) \
               + glob.glob(os.path.join(os.path.join(base_dir, 'aes'), "*.h")) \
               + glob.glob(os.path.join(os.path.join(base_dir, 'monero'), "*.h"))

    args = [
        'clang2py',
        '--clang-args=%s' % quote(' '.join(clang_args)),
        '-o%s' % quote(types_fname),
    ]
    for cf in h_files:
        args.append(quote(cf))

    print(' '.join(args))

    _back = sys.argv
    sys.argv = args
    clang2py.main()
    sys.argv = _back

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

