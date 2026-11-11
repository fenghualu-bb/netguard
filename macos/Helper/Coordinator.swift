import Foundation
import NetGuardCore
import Darwin

final class Coordinator {
    private let queue = DispatchQueue(label: "app.netguard.coordinator")
    private let settings: ConfigurationStore?
    private let policy: PolicyFileStore?
    private var state = DurableState()
    private var ready = false
    private var engine = PolicyEngine(lockdown: true)
    private var current: PolicySnapshot?
    private var heartbeats: [String: TimeInterval] = [:]
    private var observedExit: String?
    private var exitObservedAt: TimeInterval = 0
    private var probing = false
    private var permits: [TransportPermit] = []
    private var timer: DispatchSourceTimer?

    init() {
        if let dir = try? PlatformPaths.policyDirectory() {
            settings = ConfigurationStore(directory: dir)
            policy = PolicyFileStore(directory: dir)
            if let loaded = try? settings?.load() {
                state = loaded
                // Restart is always locked, including after an unclean shutdown.
                state.lockdown = true
                if (try? settings?.save(state)) != nil { ready = true }
            }
        } else { settings = nil; policy = nil }
        engine = PolicyEngine(configuration: state.configuration, lockdown: true)
        let clock = DispatchSource.makeTimerSource(queue: queue)
        clock.schedule(deadline: .now(), repeating: .seconds(1))
        clock.setEventHandler { [weak self] in self?.tick() }
        timer = clock
        clock.resume()
    }

    private func tick() {
        guard ready, let policy, let settings else { current = nil; return }
        let now = ProcessInfo.processInfo.systemUptime
        let boot = PlatformPaths.bootSessionID()
        guard !boot.isEmpty else { current = nil; return }
        if !probing && now - exitObservedAt >= 5 {
            probing = true
            TraceProbe.fetch { [weak self] values in
                self?.queue.async {
                    guard let self else { return }
                    self.probing = false
                    self.exitObservedAt = ProcessInfo.processInfo.systemUptime
                    self.observedExit = values.count == 2 && values[0] != nil && values[0] == values[1] ? values[0] : nil
                }
            }
        }
        // No currently reliable Claude-route measurement, TUN owner, or real
        // machine receipt exists. Never substitute a generic utun or a build flag.
        let evidence = RuntimeEvidence(observedAt: now,
            ordinaryExitIP: now - exitObservedAt <= 10 ? observedExit : nil,
            socketFilterVerified: now - (heartbeats["socket"] ?? -100) <= 3,
            packetFilterVerified: now - (heartbeats["packet"] ?? -100) <= 3)
        permits.removeAll { $0.expiresAt <= now }
        let snapshot = engine.evaluate(evidence: evidence, now: now, bootSessionID: boot, transportPermits: permits)
        if snapshot.lockdown != state.lockdown {
            state.lockdown = snapshot.lockdown
            do { try settings.save(state) } catch { ready = false; current = nil; return }
        }
        do { try policy.write(snapshot); current = snapshot } catch { current = nil }
    }

    func status(_ reply: @escaping (Data?, String?) -> Void) {
        queue.async {
            guard let current = self.current,
                  current.expiresAt > ProcessInfo.processInfo.systemUptime else { reply(nil, "策略不可用或已过期。") ; return }
            reply(try? JSONEncoder().encode(current), nil)
        }
    }
    func diagnostics(_ reply: @escaping (Data?, String?) -> Void) {
        queue.async {
            let status = self.current.map { "phase=\($0.phase.rawValue)\nlockdown=\($0.lockdown)\nsocketHeartbeat=\($0.evidence.socketFilterVerified)\npacketHeartbeat=\($0.evidence.packetFilterVerified)\n" } ?? "policy=unavailable\n"
            reply(Data((status + "tunOwnership=unverified\nclaudeExit=unverified\nrealMachineAcceptance=unverified\n").utf8), nil)
        }
    }
    func configure(_ data: Data, authorization: Data, reply: @escaping (Bool, String?) -> Void) {
        guard AuthorizationVerifier.verify(authorization) else { reply(false, "管理员授权无效。"); return }
        queue.async {
            guard self.ready, let settings = self.settings, data.count <= 262144,
                  var config = try? JSONDecoder().decode(GuardConfiguration.self, from: data) else { reply(false, "配置或存储不可用。"); return }
            let errors = config.validationErrors()
            guard errors.isEmpty else { reply(false, errors.joined(separator: ", ")); return }
            guard self.state.configuration.revision < UInt64.max else { reply(false, "配置版本已耗尽。"); return }
            config.revision = self.state.configuration.revision + 1
            let next = DurableState(configuration: config, lockdown: true)
            do {
                try settings.save(next)
                self.state = next
                self.engine = PolicyEngine(configuration: config, lockdown: true)
                self.tick()
                reply(true, nil)
            } catch { reply(false, "无法安全保存配置。") }
        }
    }
    func release(authorization: Data, reply: @escaping (Bool, String?) -> Void) {
        guard AuthorizationVerifier.verify(authorization) else { reply(false, "管理员授权无效。"); return }
        queue.async {
            guard self.ready, let settings = self.settings, let current = self.current else { reply(false, "缺少最新策略。"); return }
            let now = ProcessInfo.processInfo.systemUptime
            do {
                var proposed = self.engine
                try proposed.requestRelease(evidence: current.evidence, now: now)
                var next = self.state; next.lockdown = false
                try settings.save(next)
                self.state = next; self.engine = proposed
                self.tick()
                reply(true, nil)
            } catch { reply(false, "当前证据不足，锁定仍然有效。") }
        }
    }
    func reportProvider(_ data: Data, role: String, reply: @escaping (Bool, String?) -> Void) {
        guard data.count <= 4096, let report = try? JSONDecoder().decode(ProviderReport.self, from: data), report.provider == role else { reply(false, "提供者身份或报告格式不符。"); return }
        queue.async {
            let now = ProcessInfo.processInfo.systemUptime
            guard !report.bootSessionID.isEmpty, report.bootSessionID == PlatformPaths.bootSessionID(),
                  report.observedAt.isFinite, report.observedAt <= now, now - report.observedAt <= 3 else { reply(false, "提供者报告过期或启动会话不符。"); return }
            self.heartbeats[role] = report.observedAt
            reply(true, nil)
        }
    }
    func reportFlow(_ data: Data, reply: @escaping (Bool, String?) -> Void) {
        guard data.count <= 8192, let report = try? JSONDecoder().decode(FlowReport.self, from: data) else { reply(false, "连接报告无效。"); return }
        queue.async {
            let now = ProcessInfo.processInfo.systemUptime
            let p = report.permit
            guard self.ready, self.state.configuration.enabled,
                  !PlatformPaths.bootSessionID().isEmpty,
                  let heartbeat = self.heartbeats["socket"], heartbeat <= now, now - heartbeat <= 3,
                  self.state.configuration.applications.contains(where: { $0.role == .proxy && IdentityMatcher.matches(report.identity, trusted: $0.identity) }),
                  p.expiresAt.isFinite, p.expiresAt > now, p.expiresAt - now <= 3,
                  p.sourcePort > 0, p.destinationPort > 0, p.ipProtocol == 6 || p.ipProtocol == 17,
                  let a = Self.addressFamily(p.sourceAddress), let b = Self.addressFamily(p.destinationAddress), a == b else {
                reply(false, "代理身份或连接元组未经验证。"); return
            }
            let reverse = TransportPermit(sourceAddress: p.destinationAddress, sourcePort: p.destinationPort,
                destinationAddress: p.sourceAddress, destinationPort: p.sourcePort,
                ipProtocol: p.ipProtocol, expiresAt: p.expiresAt)
            self.permits.removeAll { $0.expiresAt <= now || $0 == p || $0 == reverse }
            guard self.permits.count <= 1022 else { reply(false, "连接许可数量已达上限。"); return }
            self.permits.append(contentsOf: [p, reverse])
            reply(true, nil)
        }
    }
    private static func addressFamily(_ text: String) -> Int32? {
        var a = in_addr(); var b = in6_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &a) }) == 1 {
            let octets = withUnsafeBytes(of: &a) { Array($0) }
            guard octets[0] != 0, octets[0] != 127, octets[0] < 224 else { return nil }
            return AF_INET
        }
        if text.withCString({ inet_pton(AF_INET6, $0, &b) }) == 1 {
            let octets = withUnsafeBytes(of: &b) { Array($0) }
            guard octets.contains(where: { $0 != 0 }), octets[0] != 0xff,
                  !(octets.dropLast().allSatisfy({ $0 == 0 }) && octets.last == 1) else { return nil }
            return AF_INET6
        }
        return nil
    }
}
