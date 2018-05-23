import sys
import os
import subprocess
import errno
import glob
from setuptools import setup, find_packages, Extension
from setuptools.command.test import test as TestCommand
from distutils.command.build_ext import build_ext


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = None

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args or '')
        sys.exit(errno)


class CTypes(Extension):
    pass


class BuildCtypeExt(build_ext):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ctypes = None

    def build_extension(self, ext):
        self._ctypes = isinstance(ext, CTypes)
        return super().build_extension(ext)

    def get_export_symbols(self, ext):
        if self._ctypes:
            return ext.export_symbols
        return super().get_export_symbols(ext)

    def get_ext_filename(self, ext_name):
        # if self._ctypes:
        #     return ext_name + '.so'
        return super().get_ext_filename(ext_name)


def rel_setup(path):
    return os.path.relpath(path, os.path.abspath(os.path.dirname(__file__)))


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


setup_dir = os.path.dirname(__file__)
base_dir = os.path.join(os.path.dirname(__file__), 'src')
CPPS = glob.glob(os.path.join(base_dir, "*.c")) \
          + glob.glob(os.path.join(os.path.join(base_dir, 'aes'), "*.c")) \
          + glob.glob(os.path.join(os.path.join(base_dir, 'ed25519-donna'), "*.c"))\
          + glob.glob(os.path.join(os.path.join(base_dir, 'monero'), "*.c"))


# see args descriptions at
# https://docs.python.org/3/distutils/apiref.html#distutils.core.Extension
sodium_flags = libsodium_flags()
CPPS = remove_files(CPPS, ['rfc6979.c'])
CPPS = [rel_setup(x) for x in CPPS]

extensions = [
    # this compiles the code for the ctypes example
    CTypes(
        name='trezor_crypto.tcry_ctype',
        sources=CPPS,
        include_dirs=['src/'],
        extra_compile_args=[
                        '--std=c99',
                        '-fPIC',
                        '-DUSE_MONERO=1',
                        '-DUSE_KECCAK=1',
                        '-DUSE_LIBSODIUM',
                        '-DSODIUM_STATIC=1',
                        '-DRAND_PLATFORM_INDEPENDENT=1',
                        '-I.',
                        '-I%s' % base_dir] + sodium_flags[0],
        extra_link_args=[] + sodium_flags[1]
    )
    ]


try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
    long_description = long_description.replace("\r", '')

except(IOError, ImportError):
    import io
    with io.open('README.md', encoding='utf-8') as f:
        long_description = f.read()


setup(
    name='py_trezor_crypto_ph4',
    version='0.0.2',
    description='Trezor-crypto python binding',
    long_description=long_description,
    url='https://github.com/ph4r05/py-trezor-crypto',
    author='Dusan Klinec',
    author_email='dusan.klinec@gmail.com',
    license='MIT',
    include_package_data=True,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Security',
    ],
    packages=find_packages(),
    # ext_modules=cythonize(extensions),
    ext_modules=extensions,
    setup_requires=['cffi >= 1.1'],
    cffi_modules=[os.path.join(setup_dir, 'trezor_crypto', 'cffi_build.py') + ':ffi'],
    install_requires=['cffi >= 1.1', 'cython >= 0.23', 'shlib', 'ctypeslib2', 'pycparser'],
    tests_require=['pytest >= 2.7.3'],
    cmdclass={
        'test': PyTest,
        # 'build_ext': BuildCtypeExt,
    })


