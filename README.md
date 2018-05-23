# Trezor-crypto python binding

This is the ctypes and cffi python binding for [trezor-crypto] used in Monero implementation.

The python module builds trezor-crypto as a shared library. Currently only ctypes is fully supported. CFFI
module is built but the python method wrappers are not implemented yet (no the roadmap).

The module automatically generates the bindings from the [trezor-crypto] header files using
[ctypeslib2] and [pycparser].

Note the forked version of the original trezor-crypto is used in order to support library mode (for now).


## Requirements:

- `gcc` / `clang`
- `pkg-config`
- `libsodium`


In order to use this module please install `libsodium`.

```bash
sudo apt-get install libsodium-dev
```

## Pypi

```bash
pip install py_trezor_crypto_ph4
```

## Dev Requirements:

In order to generate bindings from the [trezor-crypto] header files the following tools are needed:

- clang
- ctypeslib2
- pycparser
- `libclang.so` / `libclang.dylib`


## Roadmap

- Code generate CFFI wrappers in the similar manner as ctype wrappers.


## Refresh Ctype bindings

In order to refresh method definitions and regenerate ctype wrappers from [trezor-crypto] header files run

```bash
python trezor_crypto/cffi_build.py -a ctypes --debug
```

## Refresh CFFI bindings

In order to refresh `data/cffi.h` from [trezor-crypto] header files run:

```bash
python trezor_crypto/cffi_build.py -a cffi_h --debug
```


[trezor-crypto]: https://github.com/ph4r05/trezor-crypto
[ctypeslib2]: https://github.com/trolldbois/ctypeslib
[pycparser]: https://github.com/eliben/pycparser



