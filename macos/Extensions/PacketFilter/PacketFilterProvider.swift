import Foundation
import Network
import NetworkExtension
import NetGuardCore

final class PacketFilterProvider: NEFilterPacketProvider {
    private var policyCache: PolicyCache?
    private let channel = ProviderChannel(provider: "packet")

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        do {
            let cache = PolicyCache(store: PolicyFileStore(directory: try PlatformPaths.policyDirectory()))
            cache.start()
            policyCache = cache
            packetHandler = { _, interface, _, bytes, length in
                guard length > 0, length <= 65_575,
                      let packet = PacketParser.parse(Data(bytes: bytes, count: length)),
                      let name = nw_interface_get_name(interface) else { return .drop }
                let networkInterface = NetworkInterface(name: String(cString: name),
                    index: nw_interface_get_index(interface),
                    isLoopback: nw_interface_get_type(interface) == nw_interface_type_loopback)
                let now = ProcessInfo.processInfo.systemUptime
                return PacketPolicy.evaluate(packet: packet, interface: networkInterface,
                    snapshot: cache.snapshot(now: now), now: now).verdict == .allow ? .allow : .drop
            }
            try channel.start()
            completionHandler(nil)
        } catch {
            packetHandler = { _, _, _, _, _ in .drop }
            policyCache?.stop()
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        packetHandler = { _, _, _, _, _ in .drop }
        channel.stop()
        policyCache?.stop()
        completionHandler()
    }
}

@main
struct PacketExtensionMain {
    static func main() {
        NEProvider.startSystemExtensionMode()
        dispatchMain()
    }
}
