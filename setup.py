import sys
from Cython.Build import cythonize
from setuptools import setup, find_packages, Extension
from setuptools.command.test import test as TestCommand


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


# see args descriptions at
# https://docs.python.org/3/distutils/apiref.html#distutils.core.Extension
extensions = [
    # this compiles the code for the ctypes example
    Extension(
        name='trezor_crypto.ctypes._cext',
        sources=['src/address.c'],
        include_dirs=['src/'],
        extra_compile_args=['--std=c99', '-DUSE_MONERO=1', '-DUSE_KECCAK=1', '-I.', '-Isrc/']),
    ]

setup(
    name='trezor_crypto',
    version='0.0.1',
    packages=find_packages(),
    ext_modules=cythonize(extensions),
    setup_requires=['cffi >= 1.1'],
    cffi_modules=['trezor_crypto/cffi_build.py:ffi'],
    install_requires=['cffi >= 1.1', 'cython >= 0.23', 'shlib', 'ctypeslib2'],
    tests_require=['pytest >= 2.7.3'],
    cmdclass={'test': PyTest})


