# NetGuard macOS design

Approved intent: user said "按你的想法来" after the formal-source/build/test proposal. Target: Apple M2, macOS 15.8.3, existing FlClash. No available Developer Program team. This is a new native implementation, not a WFP translation. Windows 1.3.4 files remain unchanged.

## Delivery and claims

Deliver an arm64 SwiftUI app, a privileged coordinator, socket and packet Network Extension providers, a reusable Swift policy module, offline tests, an unsigned build script, and explicit signing/deployment/real-machine acceptance instructions. A build is not an installed security product. Unsigned builds must never activate extensions or display protection as verified. Never disable SIP/Gatekeeper, buy memberships, publish credentials or embed a signing key. User-approved target is parity or better; that label is earned only after the M2 real-machine matrix passes. Missing capabilities remain visible blockers, not green checks.

## Architecture

1. `macos/NetGuardCore`: pure Foundation Swift package. Typed config, process identities, observations, freshness, locked state machine, packet parsing and allow/drop policy. No OS mutation or UI dependencies. Persistent lockdown never clears itself after health recovery.
2. `macos/Platform`: shared Apple-specific identity, IPC, root-owned state file IO, and FlClash/exit observations. Privileged helper owns config, policy and redacted events. Signed clients request typed actions over XPC; privileged config/enable/release requires Authorization Services. No shell strings or arbitrary file/command execution over IPC.
3. `macos/Helper`: SMAppService LaunchDaemon coordinator, runs outside the GUI, probes both public trace domains, verifies selected FlClash/core identities and exact TUN evidence, writes monotonically revised root-owned snapshots in the entitled group container. External app crashes cause stale/unknown state, not cached permission. Audit-token identities must be verified, not claimed bundle strings.
4. `macos/Extensions`: socket-flow provider blocks protected Claude identities while locked/unknown, including already-open flows via ongoing outbound-data verdicts; packet provider blocks physical internet except explicitly verified proxy flow permits and narrow link-local control traffic. Only the identified FlClash utun is eligible, never every interface named utun. IPv4/IPv6, fragments, truncation and extension headers are parsed conservatively. Filter APIs are used as filters; no second packet-tunnel VPN.
5. `macos/App`: SwiftUI menu-bar/workbench. Separate build/signing/registration/enabled/attested states. Empty whitelist, missing peers, stale state, unsupported Claude CLI identity, missing packet/socket enforcement or unsigned binaries cannot produce a green status. Diagnostics export excludes nodes, subscription URLs, passwords and raw proxy configuration. No silent whitelist changes or automatic manual release.

## Security boundaries

- Signing identity: exact Team ID plus signing identifier after SecCode audit-token verification; unsigned binaries require an explicit verified hash pin. Never trust a process name or all binaries signed by one team. Claude app/helper inventory is validated, CLI interpreters are not treated as a uniquely protected native CLI.
- Root policy files: regular files, bounded size, reject symlinks/non-root ownership; atomic updates and monotonic timestamps. Consumers cache snapshots, not per-packet disk IO. Expired, future, incompatible or missing policy fails closed. Policy must identify the exact TUN and trusted proxy permits; the first release can stay blocked until those facts are actually validated on the Mac.
- Physical permits: validated proxy process socket tuples, not a blanket root-user exception, generic all-utun allow or arbitrary server-IPs supplied by an unauthenticated UI. Unknown flows are dropped. All default allowances are explained and tested.
- XPC: exact signed peer identifiers and Team ID; state mutation requires an authenticated admin action. Control-plane health cannot be fabricated by a same-user JSON file. A helper/filter mismatch remains blocked.
- Network changes, helper install and extension activation require a local safety warning, closure of other network apps and the user's actual macOS approval. No remote activation in CI.

## Measurable acceptance

Offline: stale/future observations, empty whitelist, dual-exit disagreement, missing TUN, identity mismatch, stale engine evidence, non-automatic unlock, unknown packet families, IPv4/v6 physical bypass, DNS, valid proxy tuples, config/event redaction, and unsigned readiness.

Mac: first installation and extension approvals; bound physical IPv4/v6 and DNS probes; LAN; proxy/TUN stop; UI/helper/provider crash independently; root-owned config tampering; sleep/wake; Wi-Fi↔Ethernet changes; Claude app/CLI upgrade; already-open streams when lockdown fires; release only after fresh dual probes, both providers and current identities pass. No claim of crash-persistent kernel enforcement from a merely enabled NE preference. Any failed critical row blocks a parity claim and production activation.

## Dependencies and research

Use Apple frameworks and SwiftPM; no third-party proxy engine is bundled and no GPL source is copied. LuLu was examined for signed identity/extension lifecycle patterns, not assumed to supply a supported external policy API. Its XPC requires its own signed client. PF-only projects and periodic process killing are not accepted as equivalent guards.

Sources checked 2026-11-10: Apple TN3134 (macOS system extensions), TN3120 (packet+socket filters can coexist), Network Extensions entitlement/Developer ID requirements, NEFilterPacketHandler interface metadata, NEFilterFlow audit tokens; Objective-See LuLu GPL-3.0 and current source; SagerNet Apple client GPL scope and FlClash GPL source. References are linked in macos/README.md. Certificate provisioning and physical Mac approval are external delivery gates; source/build/tests proceed without purchasing a membership.
