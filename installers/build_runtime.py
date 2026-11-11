#!/usr/bin/env python3
"""Build pinned Linux x86_64 compatibility payloads with the installed LLVM toolchain.
SPDX-License-Identifier: GPL-3.0-only
"""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
from bridge_setup.core import CATALOG
from bridge_setup.pe import PE
from bridge_setup.util import digest, download, extract, private_json

REPO = Path(__file__).resolve().parents[1]
BUILD = REPO / 'build/installer'
CACHE = BUILD / 'downloads'


def run(args, **kwargs):
    subprocess.run([str(x) for x in args], check=True, **kwargs)


def tree(asset, name):
    archive = download(CATALOG[asset], CACHE)
    destination = BUILD / name
    if not destination.exists():
        extract(archive, destination)
    return destination


def llvm_tools():
    """Use the host LLVM toolchain without downloading a second compiler."""
    names = ('clang', 'clang++', 'lld-link', 'llvm-ar', 'llvm-ranlib', 'llvm-dlltool', 'llvm-rc')
    result = {name: shutil.which(name) for name in names}
    missing = [name for name, path in result.items() if path is None]
    if missing:
        raise RuntimeError('Missing LLVM build tools: ' + ', '.join(missing))
    return result


def build_linux_nfapi(llvm, output):
    """Preserve the packaged driver's explicit unsupported ABI alongside the core."""
    build = BUILD / 'linux-payloads'
    build.mkdir(parents=True, exist_ok=True)
    definition = build / 'driver-kernel32.def'
    definition.write_text('LIBRARY KERNEL32.dll\nEXPORTS\n SetLastError\n')
    run([llvm['llvm-dlltool'], '-m', 'i386:x86-64', '-d', definition,
         '-l', build / 'driver-kernel32.lib'])
    run([llvm['clang'], '--driver-mode=cl', '/nologo', '/c', '/O2', '/GS-',
         '/Gs9999999', '/GR-', '/EHs-c-', '/Zl', 'driver_registration.cpp',
         '/Fo' + str(build / 'driver-registration.obj')], cwd=REPO / 'shim/nfapi')
    core = REPO / 'shim/nfapi/build'
    run([llvm['lld-link'], '/dll', '/entry:DllMain', '/nodefaultlib',
         '/out:' + str(output.resolve()), core / 'nfapi_stub.obj',
         build / 'driver-registration.obj', build / 'driver-kernel32.lib',
         core / 'kernel32.lib', core / 'ws2_32.lib', core / 'iphlpapi.lib'])


def verify_linux_exports(core, packaged):
    expected = PE(core).exported_names() | {
        '?nf_registerDriver@nfapi@@YA?AW4_NF_STATUS@@PEBD@Z',
        '?nf_unRegisterDriver@nfapi@@YA?AW4_NF_STATUS@@PEBD@Z',
    }
    if PE(packaged).exported_names() != expected:
        raise RuntimeError('Packaged nfapi exports differ from the core plus driver-management ABI')


def compiler_identity(llvm):
    return {name: {'path': path, 'sha256': digest(path)} for name, path in llvm.items()}


def build_wmi(output, llvm):
    source_root = tree('wine-source', 'wine-source')
    sources = [p for p in source_root.iterdir() if (p / 'configure').is_file()]
    if len(sources) != 1:
        raise RuntimeError('Unexpected Wine source layout')
    source = sources[0]
    patch = REPO / 'wine-wbemprox/patches/0001-wbemprox-add-logicaldisk-root-directory.patch'
    marker = source / '.bridge-patched'
    if not marker.exists():
        run(['patch', '-p1', '-i', patch], cwd=source)
        marker.write_text(digest(patch))
    elif marker.read_text() != digest(patch):
        raise RuntimeError('The Wine source cache has another patch revision')
    tools = BUILD / 'bin'
    tools.mkdir(parents=True, exist_ok=True)
    def wrapper(name, body):
        path = tools / name
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(0o755)
    # Paths are generated locally and never committed or packaged.
    import shlex
    clang = shlex.quote(llvm['clang'])
    wrapper('host-cc', f'exec {clang} "$@"')
    clangxx = shlex.quote(llvm['clang++'])
    wrapper('host-c++', f'exec {clangxx} "$@"')
    wrapper('clang-cl', f'exec {clang} --driver-mode=cl "$@"')
    wrapper('x86_64-windows-clang', f'exec {clang} --target=x86_64-pc-windows-msvc -fuse-ld=lld -Wno-unused-command-line-argument "$@"')
    wrapper('x86_64-windows-clang++', f'exec {clang} --target=x86_64-pc-windows-msvc -fuse-ld=lld -Wno-unused-command-line-argument "$@"')
    for name in ('x86_64-w64-mingw32-clang', 'amd64-w64-mingw32-clang'):
        wrapper(name, f'exec {clang} --target=x86_64-pc-windows-msvc -fuse-ld=lld -Wno-unused-command-line-argument "$@"')
    for name in ('lld-link', 'x86_64-windows-lld-link', 'x86_64-pc-windows-msvc-lld-link'):
        linker = shlex.quote(llvm['lld-link'])
        wrapper(name, f'exec {linker} "$@"')
    ar = shlex.quote(llvm['llvm-ar'])
    ranlib = shlex.quote(llvm['llvm-ranlib'])
    wrapper('ar', f'exec {ar} "$@"')
    wrapper('ranlib', f'exec {ranlib} "$@"')
    for name in ('dlltool', 'llvm-dlltool', 'x86_64-windows-dlltool', 'x86_64-w64-mingw32-dlltool'):
        dlltool = shlex.quote(llvm['llvm-dlltool'])
        wrapper(name, f'exec {dlltool} "$@"')
    env = os.environ.copy()
    env['PATH'] = str(tools) + os.pathsep + env['PATH']
    bison = shutil.which('bison', path=env['PATH'])
    version = subprocess.check_output([bison, '--version'], text=True) if bison else ''
    if not version or ' 3.' not in version.splitlines()[0]:
        root = tree('bison-source', 'bison-source')
        src = next(p for p in root.iterdir() if (p / 'configure').exists())
        installed = BUILD / 'host-tools'
        if not (installed / 'bin/bison').exists():
            run([src / 'configure', '--prefix=' + str(installed)], cwd=src)
            run(['make', '-j4'], cwd=src)
            run(['make', 'install'], cwd=src)
        env['PATH'] = str(installed / 'bin') + os.pathsep + env['PATH']
    build = BUILD / 'wine-build'
    build.mkdir(exist_ok=True)
    mapping = '-ffile-prefix-map=' + str(REPO.resolve()) + '=/build/exitlag-bridge'
    configuration = build / '.bridge-compiler-v5.json'
    identity = compiler_identity(llvm)
    if not configuration.exists() or json.loads(configuration.read_text()) != identity:
        # A compiler change requires fresh import libraries and PE objects.
        shutil.rmtree(build)
        build.mkdir()
        run([source / 'configure', '--enable-archs=x86_64', '--enable-tools', '--disable-tests',
             '--without-x', '--without-wayland', '--without-freetype',
             'CC=' + str(tools / 'host-cc'), 'CXX=' + str(tools / 'host-c++'),
             'x86_64_CC=' + str(tools / 'x86_64-windows-clang')], cwd=build, env=env)
        configuration.write_text(json.dumps(identity, sort_keys=True) + '\n')
    run(['make', '-j4', 'dlls/wbemprox/x86_64-windows/wbemprox.dll',
         'x86_64_CFLAGS=-O2 ' + mapping], cwd=build, env=env)
    shutil.copy2(build / 'dlls/wbemprox/x86_64-windows/wbemprox.dll', output)
    # Corresponding source is shipped beside distributable installers.
    archive = BUILD / 'exitlag-bridge-wine-source.tar.gz'
    def normalize(info):
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        info.mtime = 0
        return info
    with tarfile.open(archive, 'w:gz') as tar:
        for path in sorted(source.rglob('*')):
            if path.is_file() and path.name != '.bridge-patched':
                tar.add(path, arcname='wine-11.17/' + str(path.relative_to(source)), recursive=False, filter=normalize)
        tar.add(Path(__file__), arcname='bridge/build_runtime.py', filter=normalize)
        tar.add(patch, arcname='bridge/wmi.patch', filter=normalize)
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('payloads',))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--toolchain', choices=('llvm',), default='llvm',
                        help='use the installed clang/lld/llvm toolchain')
    parser.add_argument('--arch', choices=('x86_64',), default='x86_64')
    args = parser.parse_args()
    if not sys.platform.startswith('linux') or platform.machine().lower() not in ('x86_64', 'amd64'):
        parser.error('Build payloads on Linux x86_64')
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    llvm = llvm_tools()
    run(['bash', REPO / 'shim/nfapi/build.sh'])
    run(['bash', REPO / 'shim/nfextlag/build.sh'])
    for name, directory in (('nfapi.dll', 'nfapi'), ('nfextlag.sys', 'nfextlag')):
        shutil.copy2(REPO / 'shim' / directory / 'build' / name, args.output / name)
    build_linux_nfapi(llvm, args.output / 'nfapi.dll')
    verify_linux_exports(REPO / 'shim/nfapi/build/nfapi.dll', args.output / 'nfapi.dll')
    payload_names = ('nfapi.dll', 'nfextlag.sys', 'wbemprox.dll')
    source_archive = build_wmi(args.output / 'wbemprox.dll', llvm)
    manifest = {'project': 'exitlag-bridge', 'version': '0.4.0',
                'wine_commit': CATALOG['wine-source']['source_commit'],
                'toolchain': args.toolchain,
                'files': {name: digest(args.output / name) for name in payload_names}}
    for name in manifest['files']:
        data = (args.output / name).read_bytes()
        for prefix in (b'/Users/', b'/home/'):
            if prefix in data or prefix.decode().encode('utf-16le') in data:
                raise RuntimeError('Release payload contains an absolute user-home reference: ' + name)
    private_json(args.output / 'manifest.json', manifest)
    print(json.dumps({'payloads_ready': True, 'corresponding_wine_source': str(source_archive)}))


if __name__ == '__main__':
    main()
