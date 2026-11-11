import Foundation
import NetGuardCore

final class ProviderChannel {
    private let queue = DispatchQueue(label: "app.netguard.provider-channel")
    private var connection: NSXPCConnection?
    private var timer: DispatchSourceTimer?
    private var registered: [String: TimeInterval] = [:]
    private let provider: String
    init(provider: String) { self.provider = provider }

    func start() throws {
        let connection = NSXPCConnection(machServiceName: BuildIdentity.machServiceName, options: .privileged)
        try PeerSecurity.secure(connection: connection, identifier: BuildIdentity.helperBundleID)
        connection.remoteObjectInterface = NSXPCInterface(with: NetGuardHelperProtocol.self)
        connection.resume()
        queue.sync {
            self.connection = connection
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now(), repeating: .seconds(1))
            timer.setEventHandler { [weak self] in self?.reportPresence() }
            self.timer = timer
            timer.resume()
        }
    }

    func stop() {
        queue.sync {
            timer?.cancel()
            timer = nil
            connection?.invalidate()
            connection = nil
            registered.removeAll()
        }
    }

    private func reportPresence() {
        let report = ProviderReport(provider: provider, observedAt: ProcessInfo.processInfo.systemUptime,
                                    bootSessionID: PlatformPaths.bootSessionID())
        guard !report.bootSessionID.isEmpty, let data = try? JSONEncoder().encode(report),
              let remote = connection?.remoteObjectProxyWithErrorHandler({ _ in }) as? NetGuardHelperProtocol else { return }
        remote.reportProvider(data) { _, _ in }
    }

    func register(_ report: FlowReport, completion: @escaping (Bool) -> Void) {
        queue.async {
            let permit = report.permit
            let key = "\(report.identity.teamID ?? "")|\(report.identity.signingIdentifier)|\(permit.ipProtocol)|\(permit.sourceAddress)|\(permit.sourcePort)|\(permit.destinationAddress)|\(permit.destinationPort)"
            let now = ProcessInfo.processInfo.systemUptime
            if let expiry = self.registered[key], expiry > now + 1 {
                completion(true)
                return
            }
            self.registered = self.registered.filter { $0.value > now }
            guard self.registered.count < 4096, let data = try? JSONEncoder().encode(report) else {
                completion(false)
                return
            }
            // Every completion and timeout is serialized, so a paused flow resumes exactly once.
            var finished = false
            let finish: (Bool) -> Void = { accepted in
                self.queue.async {
                    guard !finished else { return }
                    finished = true
                    if accepted { self.registered[key] = permit.expiresAt }
                    completion(accepted)
                }
            }
            self.queue.asyncAfter(deadline: .now() + 2) { finish(false) }
            guard let remote = self.connection?.remoteObjectProxyWithErrorHandler({ _ in finish(false) }) as? NetGuardHelperProtocol else {
                finish(false)
                return
            }
            remote.reportFlow(data) { accepted, _ in finish(accepted) }
        }
    }
}
