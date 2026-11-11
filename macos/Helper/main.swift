import Foundation

private final class Service: NSObject, NetGuardHelperProtocol {
    let coordinator: Coordinator
    let role: String
    init(_ coordinator: Coordinator, role: String) { self.coordinator = coordinator; self.role = role }
    func status(reply: @escaping (Data?, String?) -> Void) { coordinator.status(reply) }
    func diagnostics(reply: @escaping (Data?, String?) -> Void) {
        guard role == "host" else { reply(nil, "无权限。"); return }; coordinator.diagnostics(reply)
    }
    func configure(_ data: Data, authorization: Data, reply: @escaping (Bool, String?) -> Void) {
        guard role == "host" else { reply(false, "无权限。"); return }; coordinator.configure(data, authorization: authorization, reply: reply)
    }
    func releaseLock(authorization: Data, reply: @escaping (Bool, String?) -> Void) {
        guard role == "host" else { reply(false, "无权限。"); return }; coordinator.release(authorization: authorization, reply: reply)
    }
    func reportProvider(_ data: Data, reply: @escaping (Bool, String?) -> Void) {
        guard role == "socket" || role == "packet" else { reply(false, "无权限。"); return }
        coordinator.reportProvider(data, role: role, reply: reply)
    }
    func reportFlow(_ data: Data, reply: @escaping (Bool, String?) -> Void) {
        guard role == "socket" else { reply(false, "无权限。"); return }
        coordinator.reportFlow(data, reply: reply)
    }
}
private final class Listener: NSObject, NSXPCListenerDelegate {
    private let coordinator = Coordinator()
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        guard BuildIdentity.isSignedBuild,
              let peer = PeerSecurity.accept(connection: connection, allowedIdentifiers: [BuildIdentity.hostBundleID, BuildIdentity.socketBundleID, BuildIdentity.packetBundleID]) else { return false }
        let role = peer == BuildIdentity.hostBundleID ? "host" : (peer == BuildIdentity.socketBundleID ? "socket" : "packet")
        connection.exportedInterface = NSXPCInterface(with: NetGuardHelperProtocol.self)
        connection.exportedObject = Service(coordinator, role: role)
        connection.resume()
        return true
    }
}
private let delegate = Listener()
private let listener = NSXPCListener(machServiceName: BuildIdentity.machServiceName)
listener.delegate = delegate
listener.resume()
RunLoop.current.run()
