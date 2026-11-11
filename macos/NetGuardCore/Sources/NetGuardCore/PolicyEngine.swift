import Foundation

public enum IdentityMatcher {
    static func validHash(_ hash: String?) -> Bool {
        guard let hash, hash.utf8.count == 64 else { return false }
        return hash.utf8.allSatisfy { (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }
    }
    static func isRuleValid(_ rule: ApplicationIdentity) -> Bool {
        if rule.sha256 != nil { return validHash(rule.sha256) }
        return !rule.signingIdentifier.isEmpty && !(rule.teamID ?? "").isEmpty
    }
    static func rulesOverlap(_ a: ApplicationIdentity, _ b: ApplicationIdentity) -> Bool {
        if let x = a.sha256, let y = b.sha256 { return x.lowercased() == y.lowercased() }
        // A signed rule and a hash rule can identify the same executable. Reject
        // contradictory roles when both include the same signed identity.
        return !a.signingIdentifier.isEmpty && a.signingIdentifier == b.signingIdentifier && a.teamID == b.teamID
    }
    public static func matches(_ observed: ApplicationIdentity, trusted: ApplicationIdentity) -> Bool {
        guard observed.verified, isRuleValid(trusted) else { return false }
        if let pin = trusted.sha256 {
            return validHash(observed.sha256) && observed.sha256?.lowercased() == pin.lowercased()
        }
        return observed.signingIdentifier == trusted.signingIdentifier && observed.teamID == trusted.teamID
    }
}

enum Freshness {
    static let evidenceAge: TimeInterval = 5
    static let snapshotAge: TimeInterval = 2
    static func evidence(_ e: RuntimeEvidence, now: TimeInterval) -> Bool {
        now.isFinite && now >= 0 && e.observedAt.isFinite && e.observedAt >= 0 && e.observedAt <= now && now - e.observedAt <= evidenceAge
    }
    static func snapshot(_ s: PolicySnapshot, now: TimeInterval) -> Bool {
        now.isFinite && now >= 0 && s.generatedAt.isFinite && s.generatedAt >= 0 && s.expiresAt.isFinite && s.generatedAt <= now && now < s.expiresAt && s.expiresAt - s.generatedAt <= snapshotAge && !s.bootSessionID.isEmpty && evidence(s.evidence, now: now) && s.configuration.enabled && s.configuration.validationErrors().isEmpty
    }
    static func enforcement(_ e: RuntimeEvidence) -> Bool {
        guard let name = e.tunInterface, name.hasPrefix("utun"), name.dropFirst(4).allSatisfy({ $0.isNumber }), name.count > 4, let index = e.tunInterfaceIndex, index > 0 else { return false }
        return e.tunOwnershipVerified && e.proxyIdentityVerified && e.socketFilterVerified && e.packetFilterVerified && e.helperVerified && e.signingVerified && e.realMachineValidationPassed
    }
    static func health(_ c: GuardConfiguration, _ e: RuntimeEvidence, now: TimeInterval) -> Bool {
        guard c.enabled, c.validationErrors().isEmpty, evidence(e, now: now), enforcement(e), let a = e.ordinaryExitIP.flatMap(IPAddress.init), let b = e.claudeExitIP.flatMap(IPAddress.init), a == b else { return false }
        return c.allowedExitIPs.compactMap(IPAddress.init).contains(a)
    }
}
public enum ReleaseError: String, Error, Codable, Equatable, Sendable { case evidenceNotHealthy }
public struct PolicyEngine: Codable, Equatable, Sendable {
    public private(set) var configuration: GuardConfiguration
    public private(set) var lockdown: Bool
    public init(configuration: GuardConfiguration = .init(), lockdown: Bool = false) { self.configuration = configuration; self.lockdown = lockdown }
    public mutating func update(configuration: GuardConfiguration) {
        if self.configuration != configuration && (self.configuration.enabled || configuration.enabled) { lockdown = true }
        self.configuration = configuration
    }
    public mutating func evaluate(evidence: RuntimeEvidence, now: TimeInterval, bootSessionID: String, transportPermits: [TransportPermit] = []) -> PolicySnapshot {
        var phase: GuardPhase
        var reasons = configuration.validationErrors()
        if !reasons.isEmpty { phase = .unconfigured }
        else if !configuration.enabled { phase = .awaitingActivation; reasons = ["guard_disabled"] }
        else if !Freshness.evidence(evidence, now: now) { phase = .stale; reasons = ["evidence_stale_or_future"]; lockdown = true }
        else if bootSessionID.isEmpty || !Freshness.health(configuration, evidence, now: now) { phase = .unverified; reasons = ["runtime_unverified"]; lockdown = true }
        else if lockdown { phase = .locked; reasons = ["explicit_release_required"] }
        else { phase = .healthy; reasons = ["verified"] }
        if configuration.enabled && phase != .healthy { lockdown = true }
        let end = now.isFinite && Freshness.evidence(evidence, now: now) ? min(now + Freshness.snapshotAge, evidence.observedAt + Freshness.evidenceAge) : 0
        let permits = transportPermits.filter { PermitValidation.valid($0, now: now) }
        return .init(configuration: configuration, evidence: evidence, phase: phase, lockdown: lockdown, generatedAt: now.isFinite ? now : 0, expiresAt: end, bootSessionID: bootSessionID, transportPermits: permits, reasons: reasons)
    }
    public mutating func requestRelease(evidence: RuntimeEvidence, now: TimeInterval) throws {
        guard Freshness.health(configuration, evidence, now: now) else { throw ReleaseError.evidenceNotHealthy }
        lockdown = false
    }
}
public enum FlowPolicy {
    public static func shouldAllow(identity: ApplicationIdentity?, snapshot: PolicySnapshot?, now: TimeInterval) -> Bool {
        guard let s = snapshot, Freshness.snapshot(s, now: now), let identity, identity.verified else { return false }
        let matches = s.configuration.applications.filter { IdentityMatcher.matches(identity, trusted: $0.identity) }
        if matches.contains(where: { $0.role == .protectedApp }) {
            return s.phase == .healthy && !s.lockdown && Freshness.health(s.configuration, s.evidence, now: now)
        }
        if matches.contains(where: { $0.role == .proxy || $0.role == .controller }) { return true }
        // A configured identity changing team/hash must not fall through to the
        // ordinary-application path while an old protected identity is locked.
        if s.configuration.applications.contains(where: { !$0.identity.signingIdentifier.isEmpty && $0.identity.signingIdentifier == identity.signingIdentifier }) { return false }
        return Freshness.enforcement(s.evidence) && IdentityMatcher.isRuleValid(identity)
    }
}
