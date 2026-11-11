import Foundation

public enum ApplicationRole: String, Codable, Equatable, Sendable { case protectedApp, proxy, controller }
public struct ApplicationIdentity: Codable, Equatable, Sendable {
    public var signingIdentifier: String
    public var teamID: String?
    public var sha256: String?
    public var verified: Bool
    public init(signingIdentifier: String = "", teamID: String? = nil, sha256: String? = nil, verified: Bool = false) {
        self.signingIdentifier = signingIdentifier; self.teamID = teamID; self.sha256 = sha256; self.verified = verified
    }
}
public struct TrustedApplication: Codable, Equatable, Sendable {
    public var identity: ApplicationIdentity
    public var role: ApplicationRole
    public var displayName: String
    public init(identity: ApplicationIdentity = .init(), role: ApplicationRole = .protectedApp, displayName: String = "") {
        self.identity = identity; self.role = role; self.displayName = displayName
    }
}
public struct GuardConfiguration: Codable, Equatable, Sendable {
    public var allowedExitIPs: Set<String>
    public var applications: [TrustedApplication]
    public var allowLAN: Bool
    public var enabled: Bool
    public var revision: UInt64
    public init(allowedExitIPs: Set<String> = [], applications: [TrustedApplication] = [], allowLAN: Bool = false, enabled: Bool = false, revision: UInt64 = 0) {
        self.allowedExitIPs = allowedExitIPs; self.applications = applications; self.allowLAN = allowLAN; self.enabled = enabled; self.revision = revision
    }
    public func validationErrors() -> [String] {
        var errors: [String] = []
        if allowedExitIPs.isEmpty { errors.append("exit_allowlist_empty") }
        if allowedExitIPs.contains(where: { IPAddress($0) == nil }) { errors.append("exit_address_invalid") }
        if !applications.contains(where: { $0.role == .protectedApp }) { errors.append("protected_identity_missing") }
        if !applications.contains(where: { $0.role == .proxy }) { errors.append("proxy_identity_missing") }
        if applications.contains(where: { !IdentityMatcher.isRuleValid($0.identity) }) { errors.append("identity_rule_invalid") }
        for (i, a) in applications.enumerated() {
            if applications.dropFirst(i + 1).contains(where: { IdentityMatcher.rulesOverlap(a.identity, $0.identity) && a.role != $0.role }) { errors.append("identity_role_conflict"); break }
        }
        return errors
    }
}
public struct RuntimeEvidence: Codable, Equatable, Sendable {
    public var observedAt: TimeInterval
    public var ordinaryExitIP: String?
    public var claudeExitIP: String?
    public var tunInterface: String?
    public var tunInterfaceIndex: UInt32?
    public var tunOwnershipVerified: Bool
    public var proxyIdentityVerified: Bool
    public var socketFilterVerified: Bool
    public var packetFilterVerified: Bool
    public var helperVerified: Bool
    public var signingVerified: Bool
    public var realMachineValidationPassed: Bool
    public init(observedAt: TimeInterval = 0, ordinaryExitIP: String? = nil, claudeExitIP: String? = nil, tunInterface: String? = nil, tunInterfaceIndex: UInt32? = nil, tunOwnershipVerified: Bool = false, proxyIdentityVerified: Bool = false, socketFilterVerified: Bool = false, packetFilterVerified: Bool = false, helperVerified: Bool = false, signingVerified: Bool = false, realMachineValidationPassed: Bool = false) {
        self.observedAt = observedAt; self.ordinaryExitIP = ordinaryExitIP; self.claudeExitIP = claudeExitIP; self.tunInterface = tunInterface; self.tunInterfaceIndex = tunInterfaceIndex; self.tunOwnershipVerified = tunOwnershipVerified; self.proxyIdentityVerified = proxyIdentityVerified; self.socketFilterVerified = socketFilterVerified; self.packetFilterVerified = packetFilterVerified; self.helperVerified = helperVerified; self.signingVerified = signingVerified; self.realMachineValidationPassed = realMachineValidationPassed
    }
}
public enum GuardPhase: String, Codable, Equatable, Sendable { case unconfigured, awaitingActivation, unverified, healthy, locked, stale }
public struct TransportPermit: Codable, Equatable, Sendable {
    public var sourceAddress: String
    public var sourcePort: UInt16
    public var destinationAddress: String
    public var destinationPort: UInt16
    public var ipProtocol: UInt8
    public var expiresAt: TimeInterval
    public init(sourceAddress: String = "", sourcePort: UInt16 = 0, destinationAddress: String = "", destinationPort: UInt16 = 0, ipProtocol: UInt8 = 0, expiresAt: TimeInterval = 0) {
        self.sourceAddress = sourceAddress; self.sourcePort = sourcePort; self.destinationAddress = destinationAddress; self.destinationPort = destinationPort; self.ipProtocol = ipProtocol; self.expiresAt = expiresAt
    }
}
public struct PolicySnapshot: Codable, Equatable, Sendable {
    public var configuration: GuardConfiguration
    public var evidence: RuntimeEvidence
    public var phase: GuardPhase
    public var lockdown: Bool
    public var generatedAt: TimeInterval
    public var expiresAt: TimeInterval
    public var bootSessionID: String
    public var transportPermits: [TransportPermit]
    public var reasons: [String]
    public init(configuration: GuardConfiguration = .init(), evidence: RuntimeEvidence = .init(), phase: GuardPhase = .unconfigured, lockdown: Bool = true, generatedAt: TimeInterval = 0, expiresAt: TimeInterval = 0, bootSessionID: String = "", transportPermits: [TransportPermit] = [], reasons: [String] = []) {
        self.configuration = configuration; self.evidence = evidence; self.phase = phase; self.lockdown = lockdown; self.generatedAt = generatedAt; self.expiresAt = expiresAt; self.bootSessionID = bootSessionID; self.transportPermits = transportPermits; self.reasons = reasons
    }
}
public struct PacketDescriptor: Codable, Equatable, Sendable {
    public var sourceAddress: String
    public var destinationAddress: String
    public var ipProtocol: UInt8
    public var sourcePort: UInt16?
    public var destinationPort: UInt16?
    public var isFragment: Bool
    public var icmpType: UInt8?
    public var icmpCode: UInt8?
    public var hopLimit: UInt8?
    public init(sourceAddress: String = "", destinationAddress: String = "", ipProtocol: UInt8 = 0, sourcePort: UInt16? = nil, destinationPort: UInt16? = nil, isFragment: Bool = false, icmpType: UInt8? = nil, icmpCode: UInt8? = nil, hopLimit: UInt8? = nil) {
        self.sourceAddress = sourceAddress; self.destinationAddress = destinationAddress; self.ipProtocol = ipProtocol; self.sourcePort = sourcePort; self.destinationPort = destinationPort; self.isFragment = isFragment; self.icmpType = icmpType; self.icmpCode = icmpCode; self.hopLimit = hopLimit
    }
}
public struct NetworkInterface: Codable, Equatable, Sendable {
    public var name: String
    public var index: UInt32
    public var isLoopback: Bool
    public init(name: String = "", index: UInt32 = 0, isLoopback: Bool = false) { self.name = name; self.index = index; self.isLoopback = isLoopback }
}
public enum PacketVerdict: String, Codable, Equatable, Sendable { case allow, drop }
public struct PacketDecision: Codable, Equatable, Sendable {
    public var verdict: PacketVerdict
    public var reason: String
    public init(verdict: PacketVerdict = .drop, reason: String = "policy_missing") { self.verdict = verdict; self.reason = reason }
}
