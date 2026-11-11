import AppKit
import Foundation
import SwiftUI
import Security
import NetGuardCore

@MainActor
final class Workbench: ObservableObject {
    @Published var helperMessage = "尚未连接协调器。"
    @Published var helperReachable = false
    @Published var exits = ""
    @Published var protectedApp: TrustedApplication?
    @Published var proxyApp: TrustedApplication?
    @Published var allowLAN = false
    @Published var enabled = false
    @Published var phase = "未验证"
    private var connection: NSXPCConnection?

    private func remote() -> NetGuardHelperProtocol? {
        connection?.remoteObjectProxyWithErrorHandler { [weak self] _ in
            DispatchQueue.main.async { self?.helperReachable = false; self?.helperMessage = "协调器通信失败。" }
        } as? NetGuardHelperProtocol
    }
    func refresh() {
        helperReachable = false
        guard BuildIdentity.isSignedBuild else { helperMessage = "未签名构建：协调器连接和激活不可用。"; return }
        let candidate = NSXPCConnection(machServiceName: BuildIdentity.machServiceName, options: .privileged)
        do { try PeerSecurity.secure(connection: candidate, identifier: BuildIdentity.helperBundleID) }
        catch { helperMessage = "无法验证协调器身份。"; return }
        candidate.invalidationHandler = { [weak self] in DispatchQueue.main.async { self?.helperReachable = false; self?.helperMessage = "协调器不可用或未注册。" } }
        candidate.remoteObjectInterface = NSXPCInterface(with: NetGuardHelperProtocol.self)
        candidate.resume(); connection = candidate
        remote()?.status { [weak self] data, message in
            DispatchQueue.main.async {
                guard let self else { return }
                self.helperReachable = true
                if let data, let snapshot = try? JSONDecoder().decode(PolicySnapshot.self, from: data) {
                    self.phase = snapshot.phase.rawValue
                    self.helperMessage = "状态：\(snapshot.phase.rawValue)；锁定：\(snapshot.lockdown ? "是" : "否")"
                } else { self.helperMessage = message ?? "无有效状态。" }
            }
        }
    }
    func choose(_ role: ApplicationRole) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = role == .proxy ? "选择已签名的 FlClash 应用或可执行文件" : "选择已签名的 Claude 应用或原生可执行文件"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        guard let identity = CodeIdentityVerifier.identity(executable: url), identity.verified else { helperMessage = "无法验证所选程序的签名。"; return }
        let lower = url.lastPathComponent.lowercased()
        guard role != .protectedApp || !["node", "python", "python3"].contains(lower) else { helperMessage = "通用解释器不能作为 Claude CLI 身份。"; return }
        let app = TrustedApplication(identity: identity, role: role, displayName: url.lastPathComponent)
        if role == .proxy { proxyApp = app } else { protectedApp = app }
    }
    private func authorization() -> Data? {
        var ref: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else { return nil }
        defer { AuthorizationFree(ref, []) }
        let result: OSStatus = "system.privilege.admin".withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { ptr in
                var rights = AuthorizationRights(count: 1, items: ptr)
                return AuthorizationCopyRights(ref, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
            }
        }
        guard result == errAuthorizationSuccess else { return nil }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(ref, &form) == errAuthorizationSuccess else { return nil }
        return withUnsafeBytes(of: &form) { Data($0) }
    }
    func save() {
        guard helperReachable, let protectedApp, let proxyApp else { helperMessage = "请先连接协调器并选择两个已签名程序。"; return }
        let addresses = Set(exits.split(whereSeparator: { $0 == "," || $0.isWhitespace }).map(String.init))
        let config = GuardConfiguration(allowedExitIPs: addresses, applications: [protectedApp, proxyApp], allowLAN: allowLAN, enabled: enabled)
        let errors = config.validationErrors()
        guard errors.isEmpty, let data = try? JSONEncoder().encode(config) else { helperMessage = "配置无效：\(errors.joined(separator: ", "))"; return }
        guard let auth = authorization() else { helperMessage = "未取得管理员授权。"; return }
        remote()?.configure(data, authorization: auth) { [weak self] success, message in
            DispatchQueue.main.async { self?.helperMessage = success ? "配置已保存，保护仍需验证。" : (message ?? "配置失败。") }
        }
    }
    func release() {
        guard helperReachable, let auth = authorization() else { helperMessage = "未连接或未取得管理员授权。"; return }
        remote()?.releaseLock(authorization: auth) { [weak self] success, message in
            DispatchQueue.main.async { self?.helperMessage = success ? "锁定已解除。" : (message ?? "解除失败。") }
        }
    }
    func exportDiagnostics() {
        let panel = NSSavePanel(); panel.nameFieldStringValue = "NetGuard-diagnostics.txt"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let output = "NetGuard macOS\n签名构建：\(BuildIdentity.isSignedBuild ? "配置已提供（未代表运行时验证）" : "否")\n协调器响应：\(helperReachable ? "是" : "否")\n保护状态：\(phase)\nTUN 所有权：未验证\n真实机器验收：未通过\n"
        do { try output.write(to: url, atomically: true, encoding: .utf8) } catch { helperMessage = "导出失败。" }
    }
}

struct WorkbenchView: View {
    @ObservedObject var model: Workbench
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("NetGuard for macOS").font(.largeTitle.bold())
                Label("保护未验证", systemImage: "exclamationmark.shield").font(.title2).foregroundStyle(.orange)
                Text(model.helperMessage)
                Text("TUN 所有权、Claude 出口及真实机器验收尚未验证。")
                GroupBox("配置") {
                    VStack(alignment: .leading) {
                        TextField("允许的出口 IP（逗号或空格分隔）", text: $model.exits)
                        HStack { Button("选择 Claude") { model.choose(.protectedApp) }; Text(model.protectedApp?.displayName ?? "未选择") }
                        HStack { Button("选择 FlClash") { model.choose(.proxy) }; Text(model.proxyApp?.displayName ?? "未选择") }
                        Toggle("允许局域网", isOn: $model.allowLAN)
                        Toggle("启用策略", isOn: $model.enabled)
                        Text("保存需要管理员授权；更改会锁定策略。原生 Claude CLI 需单独验证，通用解释器不受保护。")
                        HStack { Button("保存配置") { model.save() }; Button("请求解除锁定") { model.release() } }
                            .disabled(!BuildIdentity.isSignedBuild || !model.helperReachable)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }
                Text("安装或激活前请关闭其他联网程序并确认网络中断风险。签名、系统授权和真实 Mac 测试仍是必要条件；此版本不提供激活。")
                HStack { Button("刷新状态") { model.refresh() }; Button("导出安全诊断") { model.exportDiagnostics() } }
            }.padding(24)
        }.frame(minWidth: 520, minHeight: 500).onAppear { model.refresh() }
    }
}
@main
struct NetGuardApp: App {
    @StateObject private var model = Workbench()
    var body: some Scene {
        WindowGroup { WorkbenchView(model: model) }
        MenuBarExtra("NetGuard", systemImage: "exclamationmark.shield") {
            Text("保护未验证"); Text(model.helperMessage)
            Button("刷新状态") { model.refresh() }
            Divider(); Button("退出 NetGuard") { NSApplication.shared.terminate(nil) }
        }
    }
}
