#!/usr/bin/env python3
"""Build the itlwm ASPM-patched kext (own component, not via tools/build.py).

Fetches the pinned upstream revision, applies the itlwm-aspm patch, builds the
kext with Xcode and copies it to build/next to the other kexts. Requires
Xcode (not just command-line tools) for the kext scheme and MacKernelSDK in
the repository root.
"""
import argparse, shutil, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'tools' / 'itlwm' / 'itlwm-aspm.patch'
PIN = '53c51c2cdd6e4b69beb91f310d74c53422b0f8bd'  # OpenIntelWireless/itlwm @ 2.4.0 bump
REPO = 'https://github.com/OpenIntelWireless/itlwm'

def run(cmd, cwd=None):
    subprocess.run([str(x) for x in cmd], check=True, cwd=cwd)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, default=ROOT / 'build' / 'itlwm.kext')
    p.add_argument('--source', type=Path, default=ROOT / 'build' / 'src' / 'itlwm')
    # The ASPM patch is RETIRED: the CNVi device advertises no ASPM capability
    # (LnkCap = 0 on Linux and macOS both), so there is nothing for it to
    # enable. Kept only as an experiment artifact; builds are stock by default.
    p.add_argument('--aspm', action='store_true', help='apply the retired itlwm-aspm patch (experiment only)')
    a = p.parse_args()
    out, src = a.out.resolve(), a.source.resolve()
    sdk = (ROOT / 'MacKernelSDK').resolve()
    if not (sdk / 'Headers').is_dir():
        raise SystemExit(f'MacKernelSDK missing at {sdk}')

    if not (src / 'itlwm').is_dir():
        src.parent.mkdir(parents=True, exist_ok=True)
        run(['git', 'init', '--quiet', src])
        run(['git', 'remote', 'add', 'origin', REPO], cwd=src)
    run(['git', 'fetch', '--quiet', '--depth', '1', 'origin', PIN], cwd=src)
    run(['git', 'checkout', '--quiet', '--force', 'FETCH_HEAD'], cwd=src)
    run(['git', 'clean', '--quiet', '--force', '-d'], cwd=src)
    if a.aspm:
        run(['patch', '-p1', '--forward', '--input', PATCH], cwd=src)
        print(f'patched {PATCH.name} at {PIN[:10]}')
    else:
        print(f'stock build (no patch) at {PIN[:10]}')

    # The project's header/library search paths are relative to the project
    # directory: expose our repository's MacKernelSDK there.
    sdk_link = src / 'MacKernelSDK'
    if not sdk_link.exists():
        sdk_link.symlink_to(sdk)
    elif sdk_link.is_symlink() and not sdk_link.exists():
        sdk_link.unlink(); sdk_link.symlink_to(sdk)

    scheme = 'itlwm'
    run(['xcodebuild', '-project', 'itlwm.xcodeproj', '-scheme', scheme,
         '-configuration', 'Release', '-derivedDataPath', 'build-xcode',
         'SYMROOT=' + str(out.parent / 'xcode'), 'build'], cwd=src)
    built = out.parent / 'xcode' / 'Release' / f'{scheme}.kext'
    if not built.is_dir():
        raise SystemExit(f'xcodebuild produced no {scheme}.kext (looked in {built})')
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(built, out)
    print(f'kext written to {out}')

if __name__ == '__main__':
    main()
