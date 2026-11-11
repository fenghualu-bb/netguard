#!/usr/bin/env python3
"""Generate public bundle metadata only. No signing keys or live proxy config."""
import argparse
import plistlib
import re
from pathlib import Path


def generate(output: Path, team: str = "", group: str = "") -> None:
    if team and not re.fullmatch(r"[A-Z0-9]{10}", team):
        raise ValueError("Team ID must contain 10 uppercase letters/digits")
    group = group or ((team + ".") if team else "UNSIGNED00.") + "group.netguard.macos"
    if not re.fullmatch(r"[A-Za-z0-9.-]{8,120}", group):
        raise ValueError("Invalid app group identifier")
    output.mkdir(parents=True, exist_ok=True)
    ids = {"host": "app.netguard.macos", "helper": "app.netguard.macos.helper",
           "socket": "app.netguard.macos.socket", "packet": "app.netguard.macos.packet"}
    service = group + ".helper"
    constants = {"teamID": team, "appGroupID": group, "hostBundleID": ids["host"],
                 "helperBundleID": ids["helper"], "socketBundleID": ids["socket"],
                 "packetBundleID": ids["packet"], "machServiceName": service}
    swift = "// Generated public build identifiers. Not an activation attestation.\npublic enum BuildIdentity {\n"
    for name, value in constants.items():
        swift += f'    public static let {name} = "{value}"\n'
    swift += f"    public static let isSignedBuild = {'true' if team else 'false'}\n}}\n"
    (output / "BuildIdentity.swift").write_text(swift, encoding="utf-8")

    def write(name, value):
        (output / name).write_bytes(plistlib.dumps(value, sort_keys=True))

    def info(identifier, executable, kind):
        return {"CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
                "CFBundleName": "NetGuard", "CFBundleDisplayName": "NetGuard",
                "CFBundlePackageType": kind, "CFBundleVersion": "100",
                "CFBundleShortVersionString": "0.1.0", "LSMinimumSystemVersion": "15.0",
                "NGTeamID": team, "NGAppGroup": group,
                "NSHumanReadableCopyright": "NetGuard local macOS development candidate"}

    app = info(ids["host"], "NetGuard", "APPL")
    app.update({"NSPrincipalClass": "NSApplication", "LSApplicationCategoryType": "public.app-category.utilities",
                "NSSystemExtensionUsageDescription": "NetGuard uses packet and application filters to prevent unintended direct connections. Activation requires your approval.",
                "LSUIElement": False})
    write("App-Info.plist", app)
    for role, module, name, provider in (("socket", "NetGuardSocket", "NetGuardSocket", "SocketFilterProvider"),
                                         ("packet", "NetGuardPacket", "NetGuardPacket", "PacketFilterProvider")):
        item = info(ids[role], name, "SYSX")
        item["NetworkExtension"] = {"NEMachServiceName": group + "." + role,
                                    "NEProviderClasses": {"com.apple.networkextension.filter-" + ("data" if role == "socket" else "packet"):
                                                          module + "." + provider}}
        write(role + "-Info.plist", item)
    base = {"com.apple.security.application-groups": [group]}
    extension = dict(base, **{"com.apple.developer.networking.networkextension": ["content-filter-provider-systemextension"]})
    write("Extension.entitlements", extension)
    app_entitlements = dict(extension, **{"com.apple.developer.system-extension.install": True,
                                         "com.apple.security.network.client": True,
                                         "com.apple.security.network.server": True})
    write("App.entitlements", app_entitlements)
    write("Helper.entitlements", dict(base, **{"com.apple.security.network.client": True,
                                             "com.apple.security.network.server": True}))
    write("Helper-LaunchDaemon.plist", {"Label": ids["helper"],
          "BundleProgram": "Contents/Library/LaunchServices/NetGuardHelper",
          "MachServices": {service: True}, "RunAtLoad": True, "KeepAlive": True,
          "ProcessType": "Background"})
    (output / "BUILD-STATUS.txt").write_text(
        "UNSIGNED DEVELOPMENT CANDIDATE: not installed, not active, not a protection attestation.\n"
        "A Team ID in metadata does not prove the bundle was signed or a profile was authorized.\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--team-id", default="")
    parser.add_argument("--app-group", default="")
    args = parser.parse_args()
    generate(args.output, args.team_id, args.app_group)
