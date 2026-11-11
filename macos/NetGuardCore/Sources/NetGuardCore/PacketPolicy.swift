import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

struct IPAddress: Equatable {
    let bytes: [UInt8]
    init?(_ text: String) {
        guard !text.isEmpty, !text.utf8.contains(0), !text.contains("%") else { return nil }
        var v4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }; return
        }
        var v6 = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return nil }
        bytes = withUnsafeBytes(of: &v6) { Array($0) }
    }
    init(bytes: [UInt8]) { self.bytes = bytes }
    var text: String {
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = bytes.withUnsafeBytes { ptr in inet_ntop(bytes.count == 4 ? AF_INET : AF_INET6, ptr.baseAddress, &buffer, socklen_t(INET6_ADDRSTRLEN)) }
        return result == nil ? "" : String(cString: buffer)
    }
    var loopback: Bool { bytes.count == 4 ? bytes[0] == 127 : bytes == [UInt8](repeating: 0, count: 15) + [1] }
    var linkLocal: Bool { bytes.count == 4 ? bytes[0] == 169 && bytes[1] == 254 : bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 }
    var local: Bool {
        if bytes.count == 4 { return bytes[0] == 10 || (bytes[0] == 172 && (16...31).contains(bytes[1])) || (bytes[0] == 192 && bytes[1] == 168) || linkLocal }
        return bytes[0] & 0xfe == 0xfc || linkLocal
    }
    var linkMulticast: Bool { bytes.count == 16 && bytes[0] == 0xff && bytes[1] == 2 }
    var unspecified: Bool { bytes.allSatisfy { $0 == 0 } }
}

public enum PacketParser {
    public static func parse(_ data: Data) -> PacketDescriptor? {
        guard !data.isEmpty, data.count <= 65589 else { return nil }
        let bytes = [UInt8](data)
        // Framing is not supplied by this API. Treat an IP-version prefix as
        // raw IP exclusively so malformed raw input cannot gain Ethernet fallback.
        // Ethernet frames with an ambiguous MAC prefix are conservatively dropped.
        if bytes[0] >> 4 == 4 || bytes[0] >> 4 == 6 { return raw(bytes) }
        guard bytes.count >= 14 else { return nil }
        let type = UInt16(bytes[12]) << 8 | UInt16(bytes[13])
        guard type == 0x0800 || type == 0x86dd else { return nil }
        let payload = Array(bytes.dropFirst(14))
        guard payload.first.map({ $0 >> 4 }) == (type == 0x0800 ? 4 : 6) else { return nil }
        return raw(payload)
    }
    private static func raw(_ b: [UInt8]) -> PacketDescriptor? {
        guard let first = b.first else { return nil }
        func u16(_ offset: Int) -> Int { Int(b[offset]) << 8 | Int(b[offset + 1]) }
        let offset: Int, total: Int, proto: UInt8, source: [UInt8], destination: [UInt8], hop: UInt8
        switch first >> 4 {
        case 4:
            // IP options are deliberately unsupported; reject rather than skip.
            guard b.count >= 20, first & 15 == 5 else { return nil }
            total = u16(2); offset = 20
            guard total >= offset, total <= b.count, b[6] & 0xbf == 0, b[7] == 0 else { return nil }
            proto = b[9]; hop = b[8]; source = Array(b[12..<16]); destination = Array(b[16..<20])
        case 6:
            guard b.count >= 40 else { return nil }
            offset = 40; total = 40 + u16(4)
            guard total > offset, total <= b.count else { return nil }
            proto = b[6]; hop = b[7]; source = Array(b[8..<24]); destination = Array(b[24..<40])
        default: return nil
        }
        let remaining = total - offset
        var sourcePort: UInt16?, destinationPort: UInt16?, icmpType: UInt8?, icmpCode: UInt8?
        switch proto {
        case 6:
            guard remaining >= 20 else { return nil }
            let header = Int(b[offset + 12] >> 4) * 4
            guard header >= 20, header <= remaining else { return nil }
            sourcePort = UInt16(u16(offset)); destinationPort = UInt16(u16(offset + 2))
        case 17:
            guard remaining >= 8, u16(offset + 4) == remaining else { return nil }
            sourcePort = UInt16(u16(offset)); destinationPort = UInt16(u16(offset + 2))
        case 1, 58:
            guard remaining >= 8, (proto == 1 && source.count == 4) || (proto == 58 && source.count == 16) else { return nil }
            icmpType = b[offset]; icmpCode = b[offset + 1]
            if proto == 58, [135, 136].contains(icmpType!), remaining < 24 { return nil }
        default:
            // Includes fragmentation, extension chains, ESP/AH and unknown L4.
            return nil
        }
        return .init(sourceAddress: IPAddress(bytes: source).text, destinationAddress: IPAddress(bytes: destination).text, ipProtocol: proto, sourcePort: sourcePort, destinationPort: destinationPort, icmpType: icmpType, icmpCode: icmpCode, hopLimit: hop)
    }
}

enum PermitValidation {
    static func valid(_ p: TransportPermit, now: TimeInterval) -> Bool {
        guard now.isFinite, p.expiresAt.isFinite, p.expiresAt > now, p.expiresAt - now <= Freshness.evidenceAge, p.sourcePort > 0, p.destinationPort > 0, p.ipProtocol == 6 || p.ipProtocol == 17, let a = IPAddress(p.sourceAddress), let b = IPAddress(p.destinationAddress), a.bytes.count == b.bytes.count, !a.unspecified, !b.unspecified, !a.loopback, !b.loopback else { return false }
        return true
    }
    static func matches(_ p: TransportPermit, packet: PacketDescriptor, now: TimeInterval) -> Bool {
        valid(p, now: now) && IPAddress(p.sourceAddress) == IPAddress(packet.sourceAddress) && IPAddress(p.destinationAddress) == IPAddress(packet.destinationAddress) && p.sourcePort == packet.sourcePort && p.destinationPort == packet.destinationPort && p.ipProtocol == packet.ipProtocol
    }
}

public enum PacketPolicy {
    public static func evaluate(packet: PacketDescriptor, interface: NetworkInterface, snapshot: PolicySnapshot?, now: TimeInterval) -> PacketDecision {
        func allow(_ reason: String) -> PacketDecision { .init(verdict: .allow, reason: reason) }
        func drop(_ reason: String) -> PacketDecision { .init(verdict: .drop, reason: reason) }
        guard !packet.isFragment, [1, 6, 17, 58].contains(packet.ipProtocol), let source = IPAddress(packet.sourceAddress), let destination = IPAddress(packet.destinationAddress), source.bytes.count == destination.bytes.count else { return drop("packet_invalid") }
        guard let s = snapshot, Freshness.snapshot(s, now: now), interface.index > 0, !interface.name.isEmpty else { return drop("policy_missing_or_stale") }
        if interface.isLoopback && source.loopback && destination.loopback { return allow("loopback") }
        if Freshness.enforcement(s.evidence), interface.name == s.evidence.tunInterface, interface.index == s.evidence.tunInterfaceIndex { return allow("verified_tun") }
        // Never treat a different tunnel as a physical-interface exception.
        guard !interface.name.hasPrefix("utun"), !interface.isLoopback else { return drop("interface_unverified") }
        if Freshness.enforcement(s.evidence), s.transportPermits.contains(where: { PermitValidation.matches($0, packet: packet, now: now) }) { return allow("proxy_transport_tuple") }
        if packet.ipProtocol == 17 && packet.sourcePort == 68 && packet.destinationPort == 67 && source.unspecified && packet.destinationAddress == "255.255.255.255" { return allow("dhcp_discovery") }
        if packet.ipProtocol == 17 && packet.sourcePort == 546 && packet.destinationPort == 547 && (source.linkLocal || source.unspecified) && destination == IPAddress("ff02::1:2") { return allow("dhcpv6_discovery") }
        if packet.ipProtocol == 58 && packet.icmpCode == 0 && packet.hopLimit == 255 && [135, 136].contains(packet.icmpType ?? 0) && (source.linkLocal || (source.unspecified && packet.icmpType == 135)) && (destination.linkLocal || destination.linkMulticast) { return allow("ipv6_neighbor_control") }
        if [6, 17].contains(packet.ipProtocol) && ([53, 853].contains(packet.destinationPort ?? 0) || [53, 853].contains(packet.sourcePort ?? 0)) { return drop("physical_dns_blocked") }
        if s.configuration.allowLAN && source.local && destination.local { return allow("explicit_lan") }
        return drop("physical_internet_blocked")
    }
}
