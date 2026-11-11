# NetGuard macOS Implementation Plan

> **For agentic workers:** Use subagent-driven-development with scoped briefs/reviews and a final integration review. Never install or activate security components during CI.

**Goal:** Deliver a native macOS 15 arm64 source/build/test candidate for the approved design, honestly gated on signing and real-Mac validation.
**Architecture:** Pure Swift policy package + privileged coordinator + dual Network Extension filters + SwiftUI workbench. Keep Windows sources unchanged.
**Tech stack:** Swift 5.9 language mode, Foundation, AppKit/SwiftUI, NetworkExtension, Security, SystemExtensions, ServiceManagement, SwiftPM, xcrun swiftc.
**Spec:** ../specs/2026-11-10-macos-guard-design.md

### Task 1: Pure policy and packet semantics

Files: `macos/NetGuardCore/Package.swift`, `Sources/NetGuardCore/*.swift`, `Tests/NetGuardCoreTests/*.swift`.
Interfaces: canonical public Codable/Sendable structs are defined in the task brief; policy cannot touch the OS. Consumers use `PolicyEngine`, `GuardConfiguration`, `RuntimeEvidence`, `PolicySnapshot`, `ApplicationIdentity`, `PacketDescriptor`, `PacketParser`, `PacketVerdict`.
- [ ] Write behavioral tests first for fresh/unknown/locked states, manual release checks, IP parsing, v4/v6/drop semantics and invalid input.
- [ ] Implement the typed package and deterministic state machine, explicit empty defaults, monotonic freshness and redacted events.
- [ ] Record unrun tests as unrun on Windows; execute with Swift on the macOS build worker before success.
- [ ] Review the actual tests/implementation and commit only this scope.

### Task 2: Native enforcement and trusted platform bridge

Files: `macos/Platform/*.swift`, `macos/Extensions/{SocketFilter,PacketFilter}/*.swift`, extension plist/entitlement templates.
Consumes: Task1 structs and the contract file. Produces typed secure XPC protocol, code identity validator, root-owned policy snapshot store/cache, two real NE providers.
- [ ] Test parser/identity-policy boundaries without opening filters.
- [ ] Implement real providers that delegate to Core and never return allow on missing trusted policy; outbound-data processing revisits protected traffic, packet handler uses the actual egress interface.
- [ ] Require signed exact peers and root-owned snapshots; unknown/freshness/signature failures block. Implement no arbitrary shell service.
- [ ] Do not fake tuple registration or active-engine attestation; unsupported facts remain explicit blockers. Compile with the macOS SDK, correct signatures and availability from compiler results.
- [ ] Review privacy/security boundaries and commit this scope.

### Task 3: Coordinator and native workbench

Files: `macos/Helper/*.swift`, `macos/App/*.swift`, helper/app plist and entitlement templates.
Consumes: Core and Platform contracts. Produces a real launchd/XPC coordinator and SwiftUI status/config/diagnostic application with explicit readiness.
- [ ] Implement local FlClash discovery/signature inventory and dual exit probes without reading/exporting raw node credentials. Missing exact TUN ownership or transport verification must stay unavailable.
- [ ] Root coordinator owns policy, heartbeat, persisted lockdown and manual admin release; app uses signed typed XPC. No background auto-unlock.
- [ ] Implement SwiftUI workbench/menu-bar UI, no green unless both providers, signing, evidence and real-machine readiness are verified. Offline diagnostics can work without enabling protection.
- [ ] Supply activation/config/release flows guarded by real local authorization; no disable-SIP instructions.
- [ ] Review IPC, authorization and truthful presentation; commit this scope.

### Task 4: Integrate, compile and document

Files: `macos/scripts/{build,verify-bundle,sign}.sh`, `macos/README.md`, `macos/ACCEPTANCE.md`, `.github/workflows/macos-ci.yml`, repo ignore rules, source-independent contract tests.
- [ ] Build unsigned arm64 app/helper/systemextension bundles using the macOS SDK and exact shared module imports. Generate Info.plist/entitlements with public identifiers only. Signing requires explicit local identities/profile inputs, never checked-in secrets.
- [ ] Add a bounded standard macOS CI job: SwiftPM tests, full SDK compilation and bundle verification; upload an unsigned candidate clearly named as such. No install/register/enable commands in CI.
- [ ] Run Windows offline regression unchanged; scan publish files for secrets and preserve existing source hashes.
- [ ] Resolve compiler/integration failures, perform task reviews and final whole-branch review; document outstanding physical-machine/certificate gates accurately.
- [ ] Publish the feature branch and a reviewable draft PR without changing Windows main behavior; produce local handoff artifacts and update shared project memory after verified results.
