// NetGuard for macOS — menu bar icon and workbench window.
// Built on the user's Mac by install.sh:  xcrun swiftc -O -parse-as-library NetGuardApp.swift
// The app runs as the normal user and only READS /Library/NetGuard/status.json and
// events.jsonl. Every change goes through /Library/NetGuard/bin/netguard with the macOS
// administrator prompt (the equivalent of UAC on Windows).

import AppKit
import SwiftUI

let ngRoot = "/Library/NetGuard"
let ngCLI = "/Library/NetGuard/bin/netguard"
let recoverCommand = "/Applications/NetGuard 紧急恢复.command"

// MARK: - Data

struct NGIntegrity: Decodable {
    var pf_enabled: Bool?
    var main_anchor_ref: Bool?
    var rules_match: Bool?
    var rule_count: Double?
    var token_live: Bool?
    var complete: Bool?
    var error: String?
    var read_error: String?
}

struct NGGuard: Decodable {
    var enabled: Bool?
    var lockdown: Bool?
    var since: Double?
    var reasons: [String]?
    var bad_streak: Double?
    var last_check: Double?
    var last_findings: [String]?
    var triggers: Double?
    var grace_until: Double?
}

struct NGCore: Decodable {
    var running: Bool?
    var privileged: Bool?
}

struct NGClaudeGuard: Decodable {
    var installed: Bool?
    var fresh: Bool?
    var age: Double?
    var state: String?
    var error: String?
}

struct NGObs: Decodable {
    var egress: String?
    var egress_ok: Bool?
    var claude_egress: String?
    var claude_egress_ok: Bool?
    var core: NGCore?
    var tun: String?
    var claudeguard: NGClaudeGuard?
}

struct NGStatus: Decodable {
    var version: String?
    var updatedAt: Double?
    var wantedKillswitch: Bool?
    var killswitchComplete: Bool?
    var integrity: NGIntegrity?
    var claudeBlock: Bool?
    var guardInfo: NGGuard?
    var observations: NGObs?
    var whitelist: [String]?
    var requireClaudeguard: Bool?
    var interval: Double?

    enum CodingKeys: String, CodingKey {
        case version
        case updatedAt = "updated_at"
        case wantedKillswitch = "wanted_killswitch"
        case killswitchComplete = "killswitch_complete"
        case integrity
        case claudeBlock = "claude_block"
        case guardInfo = "guard"
        case observations
        case whitelist
        case requireClaudeguard = "require_claudeguard"
        case interval
    }
}

struct NGReason: Decodable {
    var code: String?
    var text: String?
    var level: String?
    var why: String?
}

struct NGEvent: Decodable {
    var ts: Double?
    var source: String?
    var type: String?
    var severity: String?
    var summary: String?
    var reasons: [NGReason]?
}

enum Overall {
    case ok, warn, bad, off, stale

    var color: NSColor {
        switch self {
        case .ok: return .systemGreen
        case .warn: return .systemOrange
        case .bad: return .systemRed
        case .off: return .systemYellow
        case .stale: return .systemGray
        }
    }
    var swiftColor: Color { Color(nsColor: color) }
    var symbol: String {
        switch self {
        case .ok: return "checkmark.shield.fill"
        case .warn: return "exclamationmark.shield.fill"
        case .bad: return "xmark.shield.fill"
        case .off: return "shield.slash"
        case .stale: return "questionmark.circle"
        }
    }
}

func fmtTime(_ ts: Double?) -> String {
    guard let ts = ts, ts > 0 else { return "—" }
    let f = DateFormatter()
    f.dateFormat = "MM-dd HH:mm:ss"
    return f.string(from: Date(timeIntervalSince1970: ts))
}

let eventNames: [String: String] = [
    "trigger": "触发保护", "suspect": "发现异常", "recovered": "已恢复", "release": "解除锁定",
    "release_refused": "解除被拒", "grace": "宽限暂缓", "config": "设置", "isolate": "隔离 Claude",
    "unisolate": "解除隔离", "rules_restored": "规则恢复", "rollback": "自动回滚", "recover": "紧急恢复",
    "kill": "结束 Claude", "guard_error": "检查出错", "info": "信息",
]

final class Model: ObservableObject {
    @Published var status: NGStatus?
    @Published var events: [NGEvent] = []
    @Published var busy = false
    @Published var lastOutput = ""
    private var timer: Timer?

    init() {
        reload()
        timer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.reload()
        }
    }

    func reload() {
        let decoder = JSONDecoder()
        if let data = FileManager.default.contents(atPath: ngRoot + "/status.json"),
           let s = try? decoder.decode(NGStatus.self, from: data) {
            status = s
        } else {
            status = nil
        }
        if let data = FileManager.default.contents(atPath: ngRoot + "/events.jsonl"),
           let text = String(data: data, encoding: .utf8) {
            let lines = text.split(separator: "\n").suffix(500)
            events = Array(lines.compactMap { try? decoder.decode(NGEvent.self, from: Data($0.utf8)) }.reversed())
        }
    }

    var age: Double {
        guard let u = status?.updatedAt else { return .infinity }
        return Date().timeIntervalSince1970 - u
    }

    var overall: Overall {
        guard let s = status, age < 60 else { return .stale }
        if s.guardInfo?.lockdown == true { return .bad }
        if s.wantedKillswitch == true && s.killswitchComplete != true { return .bad }
        if s.wantedKillswitch != true { return .off }
        if !(s.guardInfo?.last_findings ?? []).isEmpty { return .warn }
        return .ok
    }

    var headline: String {
        guard let s = status else { return "NetGuard 后台未运行（没有状态文件）" }
        if age >= 60 { return "状态已 \(Int(age)) 秒未更新：后台可能已停止" }
        if s.guardInfo?.lockdown == true { return "已锁定 Claude：" + (s.guardInfo?.reasons ?? []).joined(separator: "；") }
        if s.wantedKillswitch == true && s.killswitchComplete != true { return "断网保护不完整！" }
        if s.wantedKillswitch != true { return "断网保护未开启" }
        let f = s.guardInfo?.last_findings ?? []
        if !f.isEmpty { return "有异常：" + f.joined(separator: "；") }
        return "当前检查通过（未做断线测试）"
    }

    /// Runs the root CLI through the macOS administrator prompt.
    func admin(_ args: [String], done: ((Bool, String) -> Void)? = nil) {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:/-")
        for a in args where a.unicodeScalars.contains(where: { !allowed.contains($0) }) {
            finish(false, "参数含不允许的字符：\(a)", done)
            return
        }
        let command = ([ngCLI] + args).map { "'" + $0 + "'" }.joined(separator: " ")
        let script = "do shell script \"\(command) 2>&1\" with administrator privileges"
        busy = true
        DispatchQueue.global().async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            p.arguments = ["-e", script]
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            var ok = false
            var text = ""
            do {
                try p.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                text = String(data: data, encoding: .utf8) ?? ""
                ok = p.terminationStatus == 0
            } catch {
                text = "无法启动 osascript：\(error)"
            }
            if text.contains("User canceled") || text.contains("-128") { text = "已取消（未输入密码）。" }
            DispatchQueue.main.async { self.finish(ok, text.trimmingCharacters(in: .whitespacesAndNewlines), done) }
        }
    }

    private func finish(_ ok: Bool, _ text: String, _ done: ((Bool, String) -> Void)?) {
        busy = false
        lastOutput = text
        reload()
        if let done = done { done(ok, text) } else { showResult(ok, text) }
    }
}

func showResult(_ ok: Bool, _ text: String) {
    let alert = NSAlert()
    alert.messageText = ok ? "完成" : "未完成"
    alert.informativeText = text.isEmpty ? (ok ? "操作已完成。" : "操作失败。") : String(text.suffix(3000))
    alert.alertStyle = ok ? .informational : .warning
    NSApp.activate(ignoringOtherApps: true)
    alert.runModal()
}

func confirm(_ title: String, _ text: String) -> Bool {
    let alert = NSAlert()
    alert.messageText = title
    alert.informativeText = text
    alert.addButton(withTitle: "继续")
    alert.addButton(withTitle: "取消")
    NSApp.activate(ignoringOtherApps: true)
    return alert.runModal() == .alertFirstButtonReturn
}

// MARK: - Views

struct Card<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
    }
}

struct Line: View {
    let label: String
    let value: String
    var ok: Bool? = nil
    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundColor(.secondary).frame(width: 120, alignment: .leading)
            if let ok = ok {
                Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(ok ? .green : .red)
            }
            Text(value).textSelection(.enabled)
            Spacer(minLength: 0)
        }
    }
}

struct OverviewView: View {
    @ObservedObject var model: Model
    var body: some View {
        let s = model.status
        let g = s?.guardInfo
        let o = s?.observations
        let i = s?.integrity
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Image(systemName: model.overall.symbol).font(.system(size: 34))
                        .foregroundColor(model.overall.swiftColor)
                    VStack(alignment: .leading) {
                        Text(model.headline).font(.title3).bold().fixedSize(horizontal: false, vertical: true)
                        Text("NetGuard \(s?.version ?? "?") · 上次检查 \(fmtTime(g?.last_check))")
                            .foregroundColor(.secondary).font(.caption)
                    }
                }
                Card(title: "断网保护（pf）") {
                    Line(label: "状态", value: s?.wantedKillswitch == true ? (s?.killswitchComplete == true ? "已开启，规则完整" : "已开启，但不完整") : "未开启",
                         ok: s?.wantedKillswitch == true ? (s?.killswitchComplete == true) : nil)
                    Line(label: "pf / 锚点引用", value: "\(i?.pf_enabled == true ? "已启用" : "未启用") / \(i?.main_anchor_ref == true ? "存在" : "缺失")")
                    Line(label: "规则 / token", value: "\(Int(i?.rule_count ?? 0)) 条 / \(i?.token_live == true ? "有效" : "无")")
                }
                Card(title: "自动防护") {
                    Line(label: "自动防护", value: g?.enabled == true ? "开启（每 \(Int(s?.interval ?? 10)) 秒，连续 2 次确认）" : "关闭")
                    Line(label: "锁定", value: g?.lockdown == true ? "是，\(fmtTime(g?.since)) 起" : "否", ok: g?.lockdown == true ? false : true)
                    if s?.claudeBlock == true { Line(label: "Claude", value: "已隔离（打开会被立即结束）", ok: false) }
                    if let gu = g?.grace_until, gu > Date().timeIntervalSince1970 {
                        Line(label: "宽限期", value: "至 \(fmtTime(gu))（开机/登录/唤醒后中危异常不锁定）")
                    }
                    Line(label: "累计触发", value: "\(Int(g?.triggers ?? 0)) 次")
                }
                Card(title: "出口与代理") {
                    Line(label: "普通出口", value: o?.egress ?? "未取得", ok: o?.egress_ok)
                    Line(label: "claude.ai 出口", value: o?.claude_egress ?? "未取得", ok: o?.claude_egress_ok)
                    Line(label: "FlClash 内核", value: o?.core?.running == true ? (o?.core?.privileged == true ? "运行中（root 授权）" : "运行中，未授权") : "未运行",
                         ok: o?.core?.running == true && o?.core?.privileged == true)
                    Line(label: "TUN", value: o?.tun ?? "未连接", ok: o?.tun != nil)
                    if s?.requireClaudeguard == true {
                        Line(label: "ClaudeGuard", value: o?.claudeguard?.fresh == true ? "运行中（\(o?.claudeguard?.state ?? "?")）" : "未运行或状态过期",
                             ok: o?.claudeguard?.fresh == true)
                    }
                }
                Card(title: "当前异常") {
                    let f = g?.last_findings ?? []
                    if f.isEmpty { Text("无").foregroundColor(.secondary) }
                    ForEach(f, id: \.self) { Text("• " + $0) }
                }
                HStack {
                    if s?.wantedKillswitch == true {
                        Button("关闭断网保护") {
                            if confirm("关闭断网保护？", "关闭后代理一旦断开，流量可能经真实 IP 发出；同时会解除 Claude 的锁定与隔离（不做检查）。") {
                                model.admin(["disable"])
                            }
                        }
                    } else {
                        Button("开启断网保护") {
                            if confirm("开启断网保护？", "会先预检（FlClash TUN、内核授权、出口白名单），加载规则后自检 DNS、代理出口和直连拦截；任一失败会自动恢复，不会让你断网。\n\n建议先关闭浏览器和 Claude。") {
                                model.admin(["enable"])
                            }
                        }
                    }
                    if g?.lockdown == true {
                        Button("解除锁定") { model.admin(["release"]) }
                    }
                    Button("刷新") { model.reload() }
                    Button("立即完整检查…") { model.admin(["refresh"]) }
                    Spacer()
                    if model.busy { ProgressView().controlSize(.small) }
                }
                Text("界面绿色只表示当前检查通过；真实停代理、睡眠唤醒、切换网络需另行验收。")
                    .font(.caption).foregroundColor(.secondary)
            }
            .padding(16)
        }
    }
}

struct RecordsView: View {
    @ObservedObject var model: Model
    @State private var onlyImportant = false
    var body: some View {
        VStack(alignment: .leading) {
            Toggle("只看触发/解除/回滚/恢复", isOn: $onlyImportant).padding([.top, .horizontal])
            List {
                ForEach(Array(filtered.enumerated()), id: \.offset) { _, e in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack {
                            Text(fmtTime(e.ts)).font(.system(.caption, design: .monospaced)).foregroundColor(.secondary)
                            Text(eventNames[e.type ?? ""] ?? (e.type ?? "?")).bold()
                                .foregroundColor(color(e.severity))
                            Text(e.summary ?? "").fixedSize(horizontal: false, vertical: true)
                        }
                        ForEach(Array((e.reasons ?? []).enumerated()), id: \.offset) { _, r in
                            Text("  · \(r.text ?? "")（\(r.level ?? "")）\(r.why ?? "")")
                                .font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
    }

    var filtered: [NGEvent] {
        if !onlyImportant { return model.events }
        let keep: Set<String> = ["trigger", "release", "release_refused", "rollback", "recover", "rules_restored", "config"]
        return model.events.filter { keep.contains($0.type ?? "") }
    }

    func color(_ s: String?) -> Color {
        switch s {
        case "高": return .red
        case "中": return .orange
        default: return .primary
        }
    }
}

struct MaintenanceView: View {
    @ObservedObject var model: Model
    @State private var newIP = ""
    @State private var verifyOutput = ""
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Card(title: "出口白名单") {
                    let wl = model.status?.whitelist ?? []
                    if wl.isEmpty { Text("白名单为空：断网保护和解除锁定都会被拒绝。").foregroundColor(.orange) }
                    ForEach(wl, id: \.self) { ip in
                        HStack {
                            Text(ip).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                            Spacer()
                            Button("删除") {
                                if confirm("从白名单删除 \(ip)？", "删除后，出口为该 IP 时会被判定为不在白名单。") {
                                    model.admin(["whitelist", "remove", ip])
                                }
                            }
                        }
                    }
                    HStack {
                        TextField("节点出口 IP 或网段", text: $newIP).textFieldStyle(.roundedBorder).frame(width: 240)
                        Button("添加") { model.admin(["whitelist", "add", newIP.trimmingCharacters(in: .whitespaces)]) { ok, text in
                            if ok { newIP = "" }
                            showResult(ok, text)
                        } }.disabled(newIP.trimmingCharacters(in: .whitespaces).isEmpty)
                        Button("从 ClaudeGuard 导入") { model.admin(["whitelist", "import-claudeguard"]) }
                    }
                }
                Card(title: "自动防护与真实 IP 模式") {
                    HStack {
                        if model.status?.guardInfo?.enabled == true {
                            Button("关闭自动防护") {
                                if confirm("关闭自动防护？", "不影响断网保护规则和现有锁定，但不再自动锁定 Claude。") { model.admin(["guard-off"]) }
                            }
                        } else {
                            Button("开启自动防护") { model.admin(["guard-on"]) }
                        }
                        if model.status?.claudeBlock == true {
                            Button("退出真实 IP 模式") { model.admin(["unisolate"]) }
                        } else {
                            Button("进入真实 IP 模式（隔离 Claude）") {
                                if confirm("隔离 Claude？", "会立即结束 Claude 桌面版和 Claude Code，之后打开也会被结束，直到退出真实 IP 模式（需出口回到白名单）。") {
                                    model.admin(["isolate"])
                                }
                            }
                        }
                    }
                }
                Card(title: "完整自检") {
                    HStack {
                        Button("运行完整自检（含直连拦截测试）") {
                            model.admin(["verify"]) { _, text in verifyOutput = text }
                        }
                        if model.busy { ProgressView().controlSize(.small) }
                    }
                    if !verifyOutput.isEmpty {
                        Text(verifyOutput).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Card(title: "文件与急救") {
                    HStack {
                        Button("打开 NetGuard 目录") { NSWorkspace.shared.open(URL(fileURLWithPath: ngRoot)) }
                        Button("紧急恢复（移除断网规则）") {
                            if confirm("执行紧急恢复？", "会移除 NetGuard 的全部 pf 规则并关闭断网保护。只在断网且无法恢复时使用。") {
                                NSWorkspace.shared.open(URL(fileURLWithPath: recoverCommand))
                            }
                        }
                    }
                    Text("没有网络时也可以双击“应用程序”里的“NetGuard 紧急恢复”，或在终端运行 sudo /Library/NetGuard/bin/netguard-recover")
                        .font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(16)
        }
    }
}

struct WorkbenchView: View {
    @ObservedObject var model: Model
    var body: some View {
        TabView {
            OverviewView(model: model).tabItem { Text("概览") }
            RecordsView(model: model).tabItem { Text("保护记录") }
            MaintenanceView(model: model).tabItem { Text("维护") }
        }
        .frame(minWidth: 620, minHeight: 520)
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let model = Model()
    var item: NSStatusItem!
    var window: NSWindow?
    var refresh: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        updateIcon()
        refresh = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in self?.updateIcon() }
    }

    func updateIcon() {
        guard let button = item.button else { return }
        let o = model.overall
        let image = NSImage(systemSymbolName: o.symbol, accessibilityDescription: "NetGuard")
        image?.isTemplate = true
        button.image = image
        button.contentTintColor = o == .ok ? nil : o.color
        button.toolTip = "NetGuard：" + model.headline
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        model.reload()
        menu.removeAllItems()
        let s = model.status
        let head = NSMenuItem(title: model.headline, action: nil, keyEquivalent: "")
        head.isEnabled = false
        menu.addItem(head)
        let o = s?.observations
        for line in [
            "出口：\(o?.egress ?? "未取得")\(o?.egress_ok == true ? " ✓" : " ✗")   claude.ai：\(o?.claude_egress ?? "未取得")\(o?.claude_egress_ok == true ? " ✓" : " ✗")",
            "内核：\(o?.core?.running == true ? (o?.core?.privileged == true ? "已授权" : "未授权") : "未运行")   TUN：\(o?.tun ?? "未连接")",
        ] {
            let i = NSMenuItem(title: line, action: nil, keyEquivalent: "")
            i.isEnabled = false
            menu.addItem(i)
        }
        menu.addItem(.separator())
        menu.addItem(withTitle: "打开工作台…", action: #selector(openWorkbench), keyEquivalent: "w").target = self
        if s?.wantedKillswitch == true {
            menu.addItem(withTitle: "关闭断网保护…", action: #selector(disable), keyEquivalent: "").target = self
        } else {
            menu.addItem(withTitle: "开启断网保护…", action: #selector(enable), keyEquivalent: "").target = self
        }
        if s?.guardInfo?.lockdown == true {
            menu.addItem(withTitle: "解除锁定…", action: #selector(releaseLockdown), keyEquivalent: "").target = self
        }
        menu.addItem(withTitle: "立即完整检查…", action: #selector(refreshNow), keyEquivalent: "r").target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "紧急恢复（移除断网规则）…", action: #selector(recover), keyEquivalent: "").target = self
        menu.addItem(withTitle: "退出菜单栏图标", action: #selector(quit), keyEquivalent: "q").target = self
    }

    @objc func openWorkbench() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 720, height: 620),
                             styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            w.title = "NetGuard 工作台"
            w.isReleasedWhenClosed = false
            w.contentView = NSHostingView(rootView: WorkbenchView(model: model))
            w.center()
            window = w
        }
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    @objc func enable() {
        if confirm("开启断网保护？", "会先预检，加载规则后自检；任一失败会自动恢复，不会让你断网。建议先关闭浏览器和 Claude。") {
            model.admin(["enable"])
        }
    }
    @objc func disable() {
        if confirm("关闭断网保护？", "关闭后代理一旦断开，流量可能经真实 IP 发出；同时会解除锁定与隔离（不做检查）。") {
            model.admin(["disable"])
        }
    }
    @objc func releaseLockdown() { model.admin(["release"]) }
    @objc func refreshNow() { model.admin(["refresh"]) }
    @objc func recover() {
        if confirm("执行紧急恢复？", "会移除 NetGuard 的全部 pf 规则并关闭断网保护。") {
            NSWorkspace.shared.open(URL(fileURLWithPath: recoverCommand))
        }
    }
    @objc func quit() { NSApp.terminate(nil) }
}

@main
struct NetGuardMain {
    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        app.run()
    }
}
