import Foundation
import NetworkExtension
import Darwin
import NetGuardCore

final class SocketFilterProvider: NEFilterDataProvider {
    private var policyCache: PolicyCache?
    private let channel = ProviderChannel(provider: "socket")

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            let cache = PolicyCache(store: PolicyFileStore(directory: try PlatformPaths.policyDirectory()))
            cache.start()
            policyCache = cache
            apply(NEFilterSettings(rules: [], defaultAction: .filterData)) { [weak self] error in
                guard let self else { completionHandler(PlatformError.unsafePolicy); return }
                if let error { cache.stop(); completionHandler(error); return }
                do { try self.channel.start(); completionHandler(nil) }
                catch { cache.stop(); completionHandler(error) }
            }
        } catch {
            policyCache?.stop()
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        channel.stop()
        policyCache?.stop()
        completionHandler()
    }

    private func identity(_ flow: NEFilterFlow) -> ApplicationIdentity? {
        // A present but invalid process token must not fall back to a responsible app.
        guard let token = flow.sourceProcessAuditToken ?? flow.sourceAppAuditToken else { return nil }
        return CodeIdentityVerifier.identity(auditToken: token)
    }

    private func allowed(_ flow: NEFilterFlow) -> Bool {
        let now = ProcessInfo.processInfo.systemUptime
        return FlowPolicy.shouldAllow(identity: identity(flow), snapshot: policyCache?.snapshot(now: now), now: now)
    }

    private var inspectVerdict: NEFilterNewFlowVerdict {
        .filterDataVerdict(withFilterInbound: true, peekInboundBytes: 1,
                           filterOutbound: true, peekOutboundBytes: 1)
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard allowed(flow) else { return .drop() }
        if let report = proxyReport(flow) {
            channel.register(report) { [weak self, weak flow] accepted in
                guard let self, let flow else { return }
                self.resumeFlow(flow, with: accepted && self.allowed(flow) ? self.inspectVerdict : .drop())
            }
            return .pause()
        }
        return inspectVerdict
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset: Int, readBytes: Data) -> NEFilterDataVerdict {
        guard allowed(flow) else { return .drop() }
        if let report = proxyReport(flow) { channel.register(report) { _ in } }
        // Pass only the bytes checked against this snapshot. Never grant a lifetime allow.
        return NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: 1)
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset: Int, readBytes: Data) -> NEFilterDataVerdict {
        guard allowed(flow) else { return .drop() }
        return NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: 1)
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        allowed(flow) ? NEFilterDataVerdict(passBytes: 0, peekBytes: 1) : .drop()
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        allowed(flow) ? NEFilterDataVerdict(passBytes: 0, peekBytes: 1) : .drop()
    }

    private func proxyReport(_ flow: NEFilterFlow) -> FlowReport? {
        let now = ProcessInfo.processInfo.systemUptime
        guard let socket = flow as? NEFilterSocketFlow,
              socket.direction == .outbound,
              let identity = identity(flow),
              let snapshot = policyCache?.snapshot(now: now),
              snapshot.configuration.applications.contains(where: {
                  $0.role == .proxy && IdentityMatcher.matches(identity, trusted: $0.identity)
              }),
              let local = socket.localEndpoint as? NWHostEndpoint,
              let remote = socket.remoteEndpoint as? NWHostEndpoint,
              let sourcePort = UInt16(local.port), sourcePort != 0,
              let destinationPort = UInt16(remote.port), destinationPort != 0,
              socket.socketProtocol == IPPROTO_TCP || socket.socketProtocol == IPPROTO_UDP,
              numericAddress(local.hostname), numericAddress(remote.hostname) else { return nil }
        return FlowReport(identity: identity, permit: TransportPermit(sourceAddress: local.hostname,
            sourcePort: sourcePort, destinationAddress: remote.hostname, destinationPort: destinationPort,
            ipProtocol: UInt8(socket.socketProtocol), expiresAt: now + 3))
    }

    private func numericAddress(_ string: String) -> Bool {
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return inet_pton(AF_INET, string, &ipv4) == 1 || inet_pton(AF_INET6, string, &ipv6) == 1
    }
}

@main
struct SocketExtensionMain {
    static func main() {
        NEProvider.startSystemExtensionMode()
        dispatchMain()
    }
}

