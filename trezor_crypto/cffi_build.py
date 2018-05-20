# See CFFI docs at https://cffi.readthedocs.org/en/latest/
from cffi import FFI
import subprocess
import errno
import glob
import os
import re
import sys


#
# ctypes: pip install ctypeslib2
# ./venv/bin/clang2py --clang-args='-Isrc/ -DUSE_KECCAK=1 -DUSE_MONERO=1 -I/Library/Developer/CommandLineTools/usr/lib/clang/9.1.0/include' src/monero/*.h
#


ffi = FFI()


def only_headers(headers, allowed):
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


def preprocess(headers, compiler='gcc'):
    p, t = None, None

    fake_libs = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tools/pycparser/utils/fake_libc_include'))
    args = ['-nostdinc', '-E', '-D__attribute__(x)=',
            '-I%s' % fake_libs, '-Isrc/', '-Isrc/monero',
            '-DUSE_MONERO=1', '-DUSE_KECCAK=1']

    try:
        p = subprocess.Popen([compiler] + args + headers, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  #subprocess.DEVNULL)

    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
    if p.wait() != 0:
        err = p.stderr.read().strip()
        print(err.decode('utf8'))
        raise EnvironmentError('Preprocessor error')

    t = p.stdout.read().strip()
    return t


def libsodium_flags():
    cflags = os.getenv('LIBSODIUM_CFLAGS', None)
    ldflags = os.getenv('LIBSODIUM_LDLAGS', None)
    if cflags is None:
        cflags = pkg_config(['--cflags', 'libsodium']).decode('utf8').split(' ')
    else:
        cflags = cflags.split(' ')

    if ldflags is None:
        ldflags = pkg_config(['--libs', 'libsodium']).decode('utf8').split(' ')
    else:
        ldflags = ldflags.split(' ')

    return cflags, ldflags


def filter_headers(headers, base_dir):
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


def remove_defs(headers, base_dir):
    from pycparser import c_parser, c_ast, parse_file, c_generator
    parser = c_parser.CParser()

    def coord_path(coord):
        if coord is None or coord.file is None or coord.file.startswith('<'):
            return None
        return os.path.abspath(coord.file)

    def take_coord(coord):
        pth = coord_path(coord)
        return pth is not None and pth.startswith(base_dir)

    def eval_dat(node):
        if isinstance(node, c_ast.BinaryOp):
            if node.op == '/':
                return eval_dat(node.left) // eval_dat(node.right)
            elif node.op == '+':
                return eval_dat(node.left) + eval_dat(node.right)
            elif node.op == '-':
                return eval_dat(node.left) - eval_dat(node.right)
            elif node.op == '*':
                return eval_dat(node.left) * eval_dat(node.right)
            else:
                raise ValueError('Unknown op: %s' % node.op)
        elif isinstance(node, c_ast.Constant):
            return int(node.value)
        else:
            raise ValueError('Unknown node: %s' % node)

    class ArrayEval(c_ast.NodeVisitor):
        def visit_ArrayDecl(self, node):
            dim_val = eval_dat(node.dim)
            node.dim = c_ast.Constant('int', '%s' % dim_val)

    class FuncDefVisitor(c_ast.NodeVisitor):
        def __init__(self):
            self.defs = []
            self.ar = ArrayEval()

        def visit_FuncDef(self, node):
            return  # print('%s at %s' % (node.decl.name, node.decl.coord))

        def visit_Typedef(self, node):
            print('typedef: %s %s' % (node.name, node.coord))
            if not take_coord(node.coord): return
            self.ar.visit(node)
            self.defs.append(node)

        def visit_FunDecl(self, node):
            print('fun: %s %s' % (node.decl.name, node.coord))
            if not take_coord(node.coord): return
            self.ar.visit(node)
            self.defs.append(node)

        def visit_Decl(self, node):
            print('decl: %s %s' % (node.name, node.coord))
            if not take_coord(node.coord): return
            self.ar.visit(node)
            self.defs.append(node)

    to_parse = headers.decode('utf8')

    # quick hack for sizeof
    to_parse = re.sub(r'\bsizeof\(uint8_t\)', '1', to_parse)
    to_parse = re.sub(r'\bsizeof\(uint16_t\)', '2', to_parse)
    to_parse = re.sub(r'\bsizeof\(uint32_t\)', '4', to_parse)
    to_parse = re.sub(r'\bsizeof\(uint64_t\)', '8', to_parse)

    ast = parser.parse(to_parse, debuglevel=0)
    ast.show()

    v = FuncDefVisitor()
    v.visit(ast)
    nast = c_ast.FileAST(v.defs)

    generator = c_generator.CGenerator()
    genc = generator.visit(nast)

    return genc


print('='*180)
sodium_flags = libsodium_flags()
print(sodium_flags)

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../src'))

HEADERS = glob.glob(os.path.join(base_dir, "*.h")) \
          + glob.glob(os.path.join(os.path.join(base_dir, 'aes'), "*.h")) \
          + glob.glob(os.path.join(os.path.join(base_dir, 'ed25519-donna'), "*.h"))\
          + glob.glob(os.path.join(os.path.join(base_dir, 'monero'), "*.h"))

CPPS = glob.glob(os.path.join(base_dir, "*.c")) \
          + glob.glob(os.path.join(os.path.join(base_dir, 'aes'), "*.c")) \
          + glob.glob(os.path.join(os.path.join(base_dir, 'ed25519-donna'), "*.c"))\
          + glob.glob(os.path.join(os.path.join(base_dir, 'monero'), "*.c"))

HEADERS = only_headers(HEADERS, ['monero.h'])
print(HEADERS)

# Wrapping header file for includes
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

with open('/tmp/header.h', 'w') as fh:
    fh.write(tpl)

HEADERS = ['/tmp/header.h']
parsed = preprocess(HEADERS)
parsed2 = filter_headers(parsed, base_dir)

with open('/tmp/prepro.h', 'wb') as fh:
    fh.write(parsed)
with open('/tmp/prepro2.h', 'wb') as fh:
    fh.write(parsed2)

parsed2 = remove_defs(parsed, base_dir)
with open('/tmp/prepro3.h', 'w') as fh:
    fh.write(parsed2)


# for header in HEADERS:
#     with open(header, "r") as hfile:
#         ffi.cdef(hfile.read())


# set_source is where you specify all the include statements necessary
# for your code to work and also where you specify additional code you
# want compiled up with your extension, e.g. custom C code you've written
#
# set_source takes mostly the same arguments as distutils' Extension, see:
# https://cffi.readthedocs.org/en/latest/cdef.html#ffi-set-source-preparing-out-of-line-modules
# https://docs.python.org/3/distutils/apiref.html#distutils.core.Extension
ffi.set_source(
    'trezor_crypto.cffi._cffi',
    tpl,
    include_dirs=['src/'],
    sources=['monero/monero.c'],#CPPS,
    extra_compile_args=['--std=c99',
                        '-fPIC',
                        '-DUSE_MONERO=1',
                        '-DUSE_KECCAK=1',
                        '-DUSE_LIBSODIUM',
                        '-DSODIUM_STATIC=1',
                        '-DRAND_PLATFORM_INDEPENDENT=1',
                        '-I.',
                        '-I%s' % base_dir
                        ] + sodium_flags[0],
    extra_link_args=[] + sodium_flags[1])

# declare the functions, variables, etc. from the stuff in set_source
# that you want to access from your C extension:
# https://cffi.readthedocs.org/en/latest/cdef.html#ffi-cdef-declaring-types-and-functions
# ffi.cdef(
#     """
#     int scalar_int_add(int a, int b);
#     int np_int32_add(int32_t* a, int32_t* b, int32_t* out, int size);
#     """)

ffi.cdef(parsed2)

