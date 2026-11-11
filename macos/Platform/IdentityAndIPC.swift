import Foundation
import Security
import NetGuardCore

@objc protocol NetGuardHelperProtocol {
    func status(reply: @escaping (Data?, String?) -> Void)
    func configure(_ data: Data, authorization: Data, reply: @escaping (Bool, String?) -> Void)
    func releaseLock(authorization: Data, reply: @escaping (Bool, String?) -> Void)
    func diagnostics(reply: @escaping (Data?, String?) -> Void)
    func reportProvider(_ data: Data, reply: @escaping (Bool, String?) -> Void)
    func reportFlow(_ data: Data, reply: @escaping (Bool, String?) -> Void)
}

public struct ProviderReport: Codable, Equatable, Sendable {
    public let provider: String
    public let observedAt: Double
    public let bootSessionID: String
    public init(provider: String, observedAt: Double, bootSessionID: String) {
        self.provider = provider
        self.observedAt = observedAt
        self.bootSessionID = bootSessionID
    }
}

public struct FlowReport: Codable, Equatable, Sendable {
    public let identity: ApplicationIdentity
    public let permit: TransportPermit
    public init(identity: ApplicationIdentity, permit: TransportPermit) {
        self.identity = identity
        self.permit = permit
    }
}

enum PlatformError: Error {
    case unsignedBuild, invalidIdentity, unsafePolicy, unavailableContainer, unavailableBootSession
}

enum PeerSecurity {
    private static func requirement(identifier: String) throws -> String {
        let permitted = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-"))
        guard BuildIdentity.isSignedBuild, !BuildIdentity.teamID.isEmpty,
              [identifier, BuildIdentity.teamID].allSatisfy({ !$0.isEmpty && $0.unicodeScalars.allSatisfy(permitted.contains) }) else {
            throw PlatformError.unsignedBuild
        }
        // The runtime flag is also checked against the live process below.
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(BuildIdentity.teamID)\" and identifier \"\(identifier)\""
    }

    static func secure(connection: NSXPCConnection, identifier: String) throws {
        let text = try requirement(identifier: identifier)
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess else {
            throw PlatformError.invalidIdentity
        }
        connection.setCodeSigningRequirement(text)
    }

    static func accept(connection: NSXPCConnection, allowedIdentifiers: Set<String>) -> String? {
        guard BuildIdentity.isSignedBuild else { return nil }
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: NSNumber(value: connection.processIdentifier)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code, let information = CodeIdentityVerifier.information(code: code),
              let identifier = information[kSecCodeInfoIdentifier as String] as? String,
              information[kSecCodeInfoTeamIdentifier as String] as? String == BuildIdentity.teamID,
              allowedIdentifiers.contains(identifier),
              let flags = information[kSecCodeInfoFlags as String] as? NSNumber,
              flags.uint32Value & 0x10000 != 0 else { return nil }
        do {
            let base = try requirement(identifier: identifier)
            guard let unique = information[kSecCodeInfoUnique as String] as? Data, !unique.isEmpty else { return nil }
            let hash = unique.map { String(format: "%02x", $0) }.joined()
            connection.setCodeSigningRequirement(base + " and cdhash H\"\(hash)\"")
            return identifier
        } catch { return nil }
    }
}

enum CodeIdentityVerifier {
    static func information(code: SecCode) -> [String: Any]? {
        var anchor: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &anchor) == errSecSuccess,
              SecCodeCheckValidity(code, [], anchor) == errSecSuccess else { return nil }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess else { return nil }
        return information as? [String: Any]
    }

    static func identity(auditToken: Data) -> ApplicationIdentity? {
        guard auditToken.count == 32 else { return nil }
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code, let info = information(code: code) else { return nil }
        return identity(information: info)
    }

    static func identity(executable: URL) -> ApplicationIdentity? {
        guard executable.isFileURL else { return nil }
        var code: SecStaticCode?
        var anchor: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple generic" as CFString, [], &anchor) == errSecSuccess else { return nil }
        if SecStaticCodeCreateWithPath(executable as CFURL, [], &code) == errSecSuccess,
           let code,
           SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), anchor) == errSecSuccess {
            var info: CFDictionary?
            if SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
               let values = info as? [String: Any], let identity = identity(information: values) {
                return identity
            }
        }
        guard let hash = ExecutableFingerprint.sha256(executable) else { return nil }
        return ApplicationIdentity(signingIdentifier: "", teamID: nil, sha256: hash, verified: true)
    }
    private static func identity(information: [String: Any]) -> ApplicationIdentity? {
        guard let identifier = information[kSecCodeInfoIdentifier as String] as? String,
              let team = information[kSecCodeInfoTeamIdentifier as String] as? String,
              !identifier.isEmpty, !team.isEmpty else { return nil }
        return ApplicationIdentity(signingIdentifier: identifier, teamID: team, sha256: nil, verified: true)
    }
}





