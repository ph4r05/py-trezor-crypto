import os
from distutils.sysconfig import get_config_var


# taken from https://github.com/pypa/setuptools/blob/master/setuptools/command/bdist_egg.py
NATIVE_EXTENSIONS = dict.fromkeys('.dll .so .dylib .pyd'.split())


def sorted_walk(dir):
    """Do os.walk in a reproducible way,
    independent of indeterministic filesystem readdir order
    """
    for base, dirs, files in os.walk(dir):
        dirs.sort()
        files.sort()
        yield base, dirs, files


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


def get_ext_outputs(bdist_dir=None):
    """Get a list of relative paths to C extensions in the output distro"""

    all_outputs = []
    if bdist_dir is None:
        bdist_dir = os.path.abspath(os.path.dirname(__file__))

    paths = {bdist_dir: ''}
    for base, dirs, files in sorted_walk(bdist_dir):
        for filename in files:
            if os.path.splitext(filename)[1].lower() in NATIVE_EXTENSIONS:
                all_outputs.append(paths[base] + filename)
        for filename in dirs:
            paths[os.path.join(base, filename)] = (paths[base] + filename + '/')

    return all_outputs, bdist_dir


def get_mod_suffix():
    return get_config_var('EXT_SUFFIX')  # e.g., '.cpython-36m-darwin.so'


