# NetGuard macOS — development candidate

Target: Apple silicon arm64 (user target M2), macOS 15.0+ (target machine 15.8.3), FlClash. Windows files remain unchanged. This branch is a native source/build candidate, not an installed or certified protection product.

## Readiness is explicit

Source present, SDK compilation, signing/profile authorization, extension approval, helper registration, active packet/socket filtering, exact TUN/proxy identity verification and real-machine security acceptance are separate facts. A successful build cannot turn the later facts green. Unsigned builds cannot activate protection. Missing or stale facts default to blocked/unverified.

The accepted design is in `docs/superpowers/specs/2026-11-10-macos-guard-design.md` at repository root. Production parity with Windows remains a release gate; it has not been established on the user's Mac.

## Build without changing networking

On a Mac with Xcode/Command Line Tools and Python 3:

```sh
swift test --package-path macos/NetGuardCore
python3 -m unittest discover -s macos/tests -p 'test_*.py'
bash macos/scripts/build.sh
```

Default output is `macos/build/NetGuard.app` for arm64. The build script only compiles and verifies bundle layout; it never installs, activates filters, modifies routes/PF, disables SIP/Gatekeeper or buys certificates. Standard macOS CI runs the same checks with a bounded job and creates an explicitly UNSIGNED artifact.

## Components

- `NetGuardCore`: typed configuration, identities, monotonic evidence, lockdown policy, packet parsing and decisions, tested without operating-system mutation.
- `Platform`: exact code-identity/XPC trust, root-owned bounded policy persistence and cache, shared typed protocol.
- `Extensions/SocketFilter`: protected application flows, revisited outbound decisions and proxy transport registration.
- `Extensions/PacketFilter`: per-interface IPv4/IPv6 physical bypass policy.
- `Helper`: privileged coordinator outside the GUI; no arbitrary command execution over IPC.
- `App`: native SwiftUI workbench/menu-bar UI with readiness blockers and redacted diagnostics.

## Signing and deployment gate

No developer team or private key is provided with this project. Network Extension deployment requires an appropriate Developer ID/provisioning setup and actual user approvals. Public identifiers may be supplied at build time using `NETGUARD_TEAM_ID` and `NETGUARD_APP_GROUP`; doing so does not itself sign the output. Do not put profiles, certificate files, tokens or private keys into Git. Do not disable system protections to make an unsigned build appear deployable.

Before any local installation/activation, close other network applications after an explicit risk explanation and preserve a recovery path. The user confirms macOS authorization/extension approvals. No controller automatically clears a lockdown.

Deployment and tests must satisfy [ACCEPTANCE.md](ACCEPTANCE.md). Until every critical row passes on the target Mac, the project must not be called equal/superior to Windows or used as a proven no-leak guard.

## Primary references and reuse decisions

- [Apple provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment): system-extension and direct-distribution requirements.
- [Apple filtering use cases](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers): socket/packet filtering, not abusing a second VPN provider.
- [Packet interface metadata](https://developer.apple.com/documentation/networkextension/nefilterpackethandler), [source audit tokens](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceappaudittoken).
- [Network Extension entitlements](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension).
- [LuLu](https://github.com/objective-see/LuLu) was inspected as an established GPL-3.0 reference, not copied/bundled or assumed to offer an external policy-control API.
- [SagerNet Apple client](https://github.com/SagerNet/sing-box-for-apple) and PF kill-switch projects were assessed. No proxy engine fork, GPL source or PF-only promise of parity is bundled here.

No node, proxy password, subscription, real whitelist exit, personal machine path or signing credential belongs in this directory.
