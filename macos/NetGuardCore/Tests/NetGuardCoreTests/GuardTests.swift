import Foundation
import XCTest
@testable import NetGuardCore

final class GuardTests: XCTestCase {
    let now: TimeInterval = 100
    let app = ApplicationIdentity(signingIdentifier: "test.protected", teamID: "TESTTEAM", verified: true)
    let proxy = ApplicationIdentity(signingIdentifier: "test.proxy", teamID: "TESTTEAM", verified: true)
    var config: GuardConfiguration { .init(allowedExitIPs: ["203.0.113.8"], applications: [.init(identity: app, role: .protectedApp), .init(identity: proxy, role: .proxy)], enabled: true, revision: 1) }
    var evidence: RuntimeEvidence { .init(observedAt: now, ordinaryExitIP: "203.0.113.8", claudeExitIP: "203.0.113.8", tunInterface: "utun7", tunInterfaceIndex: 17, tunOwnershipVerified: true, proxyIdentityVerified: true, socketFilterVerified: true, packetFilterVerified: true, helperVerified: true, signingVerified: true, realMachineValidationPassed: true) }
    func snapshot(_ evidence: RuntimeEvidence? = nil, locked: Bool = false, permits: [TransportPermit] = []) -> PolicySnapshot {
        var engine = PolicyEngine(configuration: config, lockdown: locked)
        return engine.evaluate(evidence: evidence ?? self.evidence, now: now, bootSessionID: "synthetic-boot", transportPermits: permits)
    }
    func testEmptyConfigurationCannotBecomeHealthy() {
        var engine = PolicyEngine()
        let result = engine.evaluate(evidence: evidence, now: now, bootSessionID: "synthetic-boot")
        XCTAssertEqual(result.phase, .unconfigured)
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: app, snapshot: result, now: now))
        var missingRules = config; missingRules.applications = []
        XCTAssertFalse(missingRules.validationErrors().isEmpty)
    }
    func testStaleFutureAndNonfiniteEvidenceRejected() {
        for time in [now - 6, now + 0.01, .infinity, .nan] {
            var e = evidence; e.observedAt = time
            XCTAssertNotEqual(snapshot(e).phase, .healthy)
        }
    }
    func testBothExitsAndEveryAttestationRequired() {
        var e = evidence; e.claudeExitIP = "203.0.113.9"
        XCTAssertTrue(snapshot(e).lockdown)
        for field in [\RuntimeEvidence.tunOwnershipVerified, \.proxyIdentityVerified, \.socketFilterVerified, \.packetFilterVerified, \.helperVerified, \.signingVerified, \.realMachineValidationPassed] {
            e = evidence; e[keyPath: field] = false
            XCTAssertNotEqual(snapshot(e).phase, .healthy)
        }
    }
    func testRecoveryAndRestartDoNotClearLockAndReleaseRechecksEvidence() throws {
        var engine = PolicyEngine(configuration: config)
        var bad = evidence; bad.claudeExitIP = nil
        XCTAssertTrue(engine.evaluate(evidence: bad, now: now, bootSessionID: "boot").lockdown)
        XCTAssertEqual(engine.evaluate(evidence: evidence, now: now, bootSessionID: "boot").phase, .locked)
        var restarted = PolicyEngine(configuration: config, lockdown: true)
        XCTAssertTrue(restarted.evaluate(evidence: evidence, now: now, bootSessionID: "boot").lockdown)
        XCTAssertThrowsError(try engine.requestRelease(evidence: evidence, now: now + 6))
        try engine.requestRelease(evidence: evidence, now: now)
        XCTAssertEqual(engine.evaluate(evidence: evidence, now: now, bootSessionID: "boot").phase, .healthy)
    }
    func testIdentifierAndTeamAndVerifiedStatusAreRequired() {
        XCTAssertTrue(IdentityMatcher.matches(app, trusted: app))
        var other = app; other.signingIdentifier = "test.unrelated"
        XCTAssertFalse(IdentityMatcher.matches(other, trusted: app))
        other = app; other.verified = false
        XCTAssertFalse(IdentityMatcher.matches(other, trusted: app))
        other = app; other.teamID = nil
        XCTAssertFalse(IdentityMatcher.matches(other, trusted: app))
    }
    func testHashPinIsExactValidAndVerified() {
        let pin = String(repeating: "a", count: 64)
        let trusted = ApplicationIdentity(sha256: pin)
        XCTAssertTrue(IdentityMatcher.matches(.init(sha256: pin, verified: true), trusted: trusted))
        XCTAssertFalse(IdentityMatcher.matches(.init(sha256: String(repeating: "b", count: 64), verified: true), trusted: trusted))
        XCTAssertFalse(IdentityMatcher.matches(.init(sha256: "invalid", verified: true), trusted: .init(sha256: "invalid")))
        XCTAssertFalse(IdentityMatcher.matches(.init(sha256: pin), trusted: trusted))
    }
    func testFlowBootstrapDoesNotReleaseProtectedApp() {
        let s = snapshot(locked: true)
        XCTAssertTrue(FlowPolicy.shouldAllow(identity: proxy, snapshot: s, now: now))
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: app, snapshot: s, now: now))
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: nil, snapshot: s, now: now))
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: proxy, snapshot: nil, now: now))
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: proxy, snapshot: s, now: now + 3))
        XCTAssertTrue(FlowPolicy.shouldAllow(identity: .init(signingIdentifier: "test.browser", teamID: "OTHER", verified: true), snapshot: s, now: now))
    }
    func testSnapshotsCannotBeFutureOrOverlong() {
        var s = snapshot(); s.generatedAt = now + 1
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: proxy, snapshot: s, now: now))
        s = snapshot(); s.expiresAt = now + 1000
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: proxy, snapshot: s, now: now))
    }
    func testDiagnosticsContainOnlyFixedReasonCodes() {
        var c = config; c.allowedExitIPs = ["SECRET-NODE-PASSWORD"]
        var engine = PolicyEngine(configuration: c)
        let s = engine.evaluate(evidence: evidence, now: now, bootSessionID: "boot")
        XCTAssertFalse(s.reasons.joined().contains("SECRET"))
    }
    let physical = NetworkInterface(name: "en0", index: 4)
    var internet: PacketDescriptor { .init(sourceAddress: "192.0.2.4", destinationAddress: "198.51.100.3", ipProtocol: 6, sourcePort: 42000, destinationPort: 443) }
    func testPhysicalInternetAndAlternateUtunDenied() {
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: physical, snapshot: snapshot(), now: now).verdict, .drop)
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: .init(name: "utun9", index: 19), snapshot: snapshot(), now: now).verdict, .drop)
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: .init(name: "utun7", index: 17), snapshot: snapshot(locked: true), now: now).verdict, .allow)
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: physical, snapshot: nil, now: now).verdict, .drop)
    }
    func testTransportPermitRequiresEveryTupleFieldAndExpiry() {
        let p = TransportPermit(sourceAddress: internet.sourceAddress, sourcePort: 42000, destinationAddress: internet.destinationAddress, destinationPort: 443, ipProtocol: 6, expiresAt: now + 1)
        let s = snapshot(permits: [p])
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: physical, snapshot: s, now: now).verdict, .allow)
        for field in [\PacketDescriptor.sourceAddress, \.destinationAddress] {
            var packet = internet; packet[keyPath: field] = "192.0.2.99"
            XCTAssertEqual(PacketPolicy.evaluate(packet: packet, interface: physical, snapshot: s, now: now).verdict, .drop)
        }
        var packet = internet; packet.sourcePort = 42001
        XCTAssertEqual(PacketPolicy.evaluate(packet: packet, interface: physical, snapshot: s, now: now).verdict, .drop)
        packet = internet; packet.destinationPort = 444
        XCTAssertEqual(PacketPolicy.evaluate(packet: packet, interface: physical, snapshot: s, now: now).verdict, .drop)
        packet = internet; packet.ipProtocol = 17
        XCTAssertEqual(PacketPolicy.evaluate(packet: packet, interface: physical, snapshot: s, now: now).verdict, .drop)
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: physical, snapshot: s, now: now + 1).verdict, .drop)
    }
    func testLANDNSBlockedAndDHCPIsNarrow() {
        var s = snapshot(); s.configuration.allowLAN = true
        let lan = PacketDescriptor(sourceAddress: "192.168.1.2", destinationAddress: "192.168.1.3", ipProtocol: 6, sourcePort: 2000, destinationPort: 80)
        XCTAssertEqual(PacketPolicy.evaluate(packet: lan, interface: physical, snapshot: s, now: now).verdict, .allow)
        var dns = lan; dns.destinationPort = 53
        XCTAssertEqual(PacketPolicy.evaluate(packet: dns, interface: physical, snapshot: s, now: now).verdict, .drop)
        let dhcp = PacketDescriptor(sourceAddress: "0.0.0.0", destinationAddress: "255.255.255.255", ipProtocol: 17, sourcePort: 68, destinationPort: 67)
        XCTAssertEqual(PacketPolicy.evaluate(packet: dhcp, interface: physical, snapshot: s, now: now).verdict, .allow)
        var wrong = dhcp; wrong.destinationAddress = "198.51.100.3"
        XCTAssertEqual(PacketPolicy.evaluate(packet: wrong, interface: physical, snapshot: s, now: now).verdict, .drop)
    }
    func testIPv6NeighborControlRequiresTypeCodeHopAndLinkScope() {
        let nd = PacketDescriptor(sourceAddress: "fe80::1", destinationAddress: "ff02::1:ff00:2", ipProtocol: 58, icmpType: 135, icmpCode: 0, hopLimit: 255)
        XCTAssertEqual(PacketPolicy.evaluate(packet: nd, interface: physical, snapshot: snapshot(), now: now).verdict, .allow)
        var bad = nd; bad.hopLimit = 64
        XCTAssertEqual(PacketPolicy.evaluate(packet: bad, interface: physical, snapshot: snapshot(), now: now).verdict, .drop)
        bad = nd; bad.icmpType = 128
        XCTAssertEqual(PacketPolicy.evaluate(packet: bad, interface: physical, snapshot: snapshot(), now: now).verdict, .drop)
    }
    func testParserIPv4IPv6AndEthernetAndMalformedInput() {
        var v4: [UInt8] = [0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,4,198,51,100,3,0xa4,0x10,0x01,0xbb,0,8,0,0]
        XCTAssertEqual(PacketParser.parse(Data(v4))?.destinationAddress, "198.51.100.3")
        XCTAssertEqual(PacketParser.parse(Data(v4))?.sourcePort, 42000)
        let ethernet = [UInt8](repeating: 0, count: 12) + [0x08,0x00] + v4
        XCTAssertNotNil(PacketParser.parse(Data(ethernet)))
        v4[6] = 0x20
        XCTAssertNil(PacketParser.parse(Data(v4)))
        v4[6] = 0; v4.removeLast()
        XCTAssertNil(PacketParser.parse(Data(v4)))
        var v6 = [UInt8](repeating: 0, count: 48)
        v6[0] = 0x60; v6[5] = 8; v6[6] = 17; v6[7] = 64
        v6[8] = 0x20; v6[9] = 1; v6[24] = 0x20; v6[25] = 1
        v6[41] = 1; v6[43] = 2; v6[45] = 8
        XCTAssertNotNil(PacketParser.parse(Data(v6)))
        for next: UInt8 in [0,43,44,50,51,60,59] {
            v6[6] = next
            XCTAssertNil(PacketParser.parse(Data(v6)))
        }
        XCTAssertNil(PacketParser.parse(Data()))
    }
}

extension GuardTests {
    func testChangedProtectedIdentityCannotEscapeIntoOrdinaryApplicationPolicy() {
        var changed = app; changed.teamID = "DIFFERENT"
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: changed, snapshot: snapshot(locked: true), now: now))
        changed = proxy; changed.teamID = "DIFFERENT"
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: changed, snapshot: snapshot(locked: true), now: now))
    }
    func testIPv6InternetMissingTUNAndExpiredGrantsFailClosed() {
        let v6 = PacketDescriptor(sourceAddress: "2001:db8::1", destinationAddress: "2001:db8::2", ipProtocol: 17, sourcePort: 5000, destinationPort: 443)
        XCTAssertEqual(PacketPolicy.evaluate(packet: v6, interface: physical, snapshot: snapshot(), now: now).verdict, .drop)
        var e = evidence; e.tunInterfaceIndex = nil
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: app, snapshot: snapshot(e), now: now))
        let permit = TransportPermit(sourceAddress: v6.sourceAddress, sourcePort: 5000, destinationAddress: v6.destinationAddress, destinationPort: 443, ipProtocol: 17, expiresAt: now)
        XCTAssertEqual(PacketPolicy.evaluate(packet: v6, interface: physical, snapshot: snapshot(permits: [permit]), now: now).verdict, .drop)
    }
    func testPersistedSnapshotAndEngineRoundTripPreserveLock() throws {
        let s = snapshot(locked: true)
        let persisted = try JSONDecoder().decode(PolicySnapshot.self, from: JSONEncoder().encode(s))
        XCTAssertTrue(persisted.lockdown)
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: app, snapshot: persisted, now: now))
        let engine = PolicyEngine(configuration: config, lockdown: true)
        let restored = try JSONDecoder().decode(PolicyEngine.self, from: JSONEncoder().encode(engine))
        XCTAssertTrue(restored.lockdown)
    }
}

extension GuardTests {
    func testMalformedRawIPCannotBeReinterpretedAsEthernet() {
        let nested: [UInt8] = [0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,4,198,51,100,3,0xa4,0x10,0x01,0xbb,0,8,0,0]
        var malformed = [UInt8](repeating: 0, count: 12) + [0x08,0x00] + nested
        malformed[0] = 0x45
        XCTAssertNil(PacketParser.parse(Data(malformed)))
    }
}

extension GuardTests {
    func testAcceptanceTransportWorksWithoutReceiptOrExitObservationsWhileProtectedAppStaysLocked() {
        var e = evidence
        e.realMachineValidationPassed = false; e.ordinaryExitIP = nil; e.claudeExitIP = nil
        e.tunInterface = nil; e.tunInterfaceIndex = nil; e.tunOwnershipVerified = false
        let permit = TransportPermit(sourceAddress: internet.sourceAddress, sourcePort: 42000, destinationAddress: internet.destinationAddress, destinationPort: 443, ipProtocol: 6, expiresAt: now + 1)
        let s = snapshot(e, permits: [permit])
        XCTAssertEqual(s.phase, .unverified)
        XCTAssertTrue(s.lockdown)
        XCTAssertTrue(FlowPolicy.shouldAllow(identity: proxy, snapshot: s, now: now))
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: app, snapshot: s, now: now))
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: physical, snapshot: s, now: now).verdict, .allow)
        var unpermitted = internet; unpermitted.destinationPort = 444
        XCTAssertEqual(PacketPolicy.evaluate(packet: unpermitted, interface: physical, snapshot: s, now: now).verdict, .drop)
        let dns = PacketDescriptor(sourceAddress: internet.sourceAddress, destinationAddress: "192.168.1.1", ipProtocol: 17, sourcePort: 42000, destinationPort: 53)
        XCTAssertEqual(PacketPolicy.evaluate(packet: dns, interface: physical, snapshot: s, now: now).verdict, .drop)
    }
    func testAcceptanceResolverUsesOnlyExactVerifiedTUNWithoutReceiptOrDualExits() {
        var e = evidence; e.realMachineValidationPassed = false; e.ordinaryExitIP = nil; e.claudeExitIP = nil
        let s = snapshot(e)
        let resolver = ApplicationIdentity(signingIdentifier: "test.resolver", teamID: "TESTSYSTEM", verified: true)
        XCTAssertTrue(FlowPolicy.shouldAllow(identity: resolver, snapshot: s, now: now))
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: app, snapshot: s, now: now))
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: .init(name: "utun7", index: 17), snapshot: s, now: now).verdict, .allow)
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: .init(name: "utun8", index: 18), snapshot: s, now: now).verdict, .drop)
        XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: physical, snapshot: s, now: now).verdict, .drop)
        e.tunOwnershipVerified = false
        XCTAssertFalse(FlowPolicy.shouldAllow(identity: resolver, snapshot: snapshot(e), now: now))
    }
    func testAcceptancePhysicalTupleStillRequiresEveryOperationalAttestation() {
        let permit = TransportPermit(sourceAddress: internet.sourceAddress, sourcePort: 42000, destinationAddress: internet.destinationAddress, destinationPort: 443, ipProtocol: 6, expiresAt: now + 1)
        for field in [\RuntimeEvidence.proxyIdentityVerified, \.socketFilterVerified, \.packetFilterVerified, \.helperVerified, \.signingVerified] {
            var e = evidence; e.realMachineValidationPassed = false; e[keyPath: field] = false
            XCTAssertEqual(PacketPolicy.evaluate(packet: internet, interface: physical, snapshot: snapshot(e, permits: [permit]), now: now).verdict, .drop)
        }
    }
}
