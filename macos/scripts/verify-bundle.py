#!/usr/bin/env python3
import argparse
import plistlib
import struct
from pathlib import Path


def verify(app: Path, architecture: str = "arm64"):
    expected = 0x0100000C if architecture == "arm64" else 0x01000007
    binaries = [app / "Contents/MacOS/NetGuard", app / "Contents/Library/LaunchServices/NetGuardHelper"]
    with (app / "Contents/Info.plist").open("rb") as stream:
        host = plistlib.load(stream)
    if host.get("CFBundleIdentifier") != "app.netguard.macos" or host.get("LSMinimumSystemVersion") != "15.0":
        raise ValueError("Unexpected host bundle identity/OS target")
    for role, executable in (("socket", "NetGuardSocket"), ("packet", "NetGuardPacket")):
        bundle = app / "Contents/Library/SystemExtensions" / ("app.netguard.macos." + role + ".systemextension")
        with (bundle / "Contents/Info.plist").open("rb") as stream:
            info = plistlib.load(stream)
        if info.get("CFBundleIdentifier") != bundle.name.removesuffix(".systemextension"):
            raise ValueError("Extension filename/identity mismatch")
        providers = info.get("NetworkExtension", {}).get("NEProviderClasses", {})
        if len(providers) != 1 or not any(executable + "." in name for name in providers.values()):
            raise ValueError("Missing concrete extension provider class")
        binaries.append(bundle / "Contents/MacOS" / executable)
    for binary in binaries:
        header = binary.read_bytes()[:8]
        if len(header) != 8 or header[:4] != b"\xcf\xfa\xed\xfe" or struct.unpack("<I", header[4:])[0] != expected:
            raise ValueError("Missing/wrong-architecture Mach-O: " + binary.name)
    if not (app / "Contents/Resources/BUILD-STATUS.txt").is_file():
        raise ValueError("Unsigned/activation boundary label missing")
    with (app / "Contents/Library/LaunchDaemons/app.netguard.macos.helper.plist").open("rb") as stream:
        helper = plistlib.load(stream)
    if helper.get("BundleProgram") != "Contents/Library/LaunchServices/NetGuardHelper":
        raise ValueError("LaunchDaemon executable path mismatch")
    return len(binaries)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("--architecture", choices=("arm64", "x86_64"), default="arm64")
    args = parser.parse_args()
    print(f"PASS {verify(args.app, args.architecture)} Mach-O binaries and unsigned bundle metadata; no activation proof")
