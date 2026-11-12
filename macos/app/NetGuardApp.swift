// NetGuard for macOS — menu bar icon and workbench window (layout mirrors the Windows workbench).
// Built on the user's Mac by install.sh:  xcrun swiftc -O -swift-version 5 -parse-as-library NetGuardApp.swift
// The app runs as the normal user and only READS /Library/NetGuard/status.json and events.jsonl.
// Every change goes through /Library/NetGuard/bin/netguard behind the macOS administrator prompt
// (the equivalent of UAC on Windows).

import AppKit
import SwiftUI

let ngRoot = "/Library/NetGuard"
let ngCLI = "/Library/NetGuard/bin/netguard"
let recoverCommand = "/Applications/NetGuard 紧急恢复.command"

// MARK: - Data (every field optional: an unexpected value must never blank the whole UI)

struct NGIntegrity: Decodable {
    var pf_enabled: Bool?
    var main_anchor_ref: Bool?
    var rules_match: Bool?
    var rule_count: Double?
    var token_live: Bool?
    var complete: Bool?
}

struct NGGuard: Decodable {
    var enabled: Bool?
    var lockdown: Bool?
    var since: Double?
    var reasons: [String]?
    var last_check: Double?
    var last_findings: [String]?
    var triggers: Double?
    var grace_until: Double?
    var duration: Double?
}

struct NGCore: Decodable {
    var running: Bool?
    var privileged: Bool?
}

struct NGFlClash: Decodable {
    var mode: String?
    var path: String?
    var mtime: Double?
}

struct NGClaudeGuard: Decodable {
    var installed: Bool?
    var fresh: Bool?
    var age: Double?
    var state: String?
    var ip: String?
    var error: String?
    var protection_enabled: Bool?
    var helper_loaded: Bool?
    var cli_hooked: Bool?
    var app_path: String?
    var app_path_ok: Bool?
    var cli_path_ok: Bool?
    var app_installed: [String]?
    var cli_installed: [String]?
}

struct NGObs: Decodable {
    var egress: String?
    var egress_ok: Bool?
    var claude_egress: String?
    var claude_egress_ok: Bool?
    var core: NGCore?
    var tun: String?
    var route: String?
    var flclash_ui: Bool?
    var flclash: NGFlClash?
    var claudeguard: NGClaudeGuard?
    var exempt_others: [String]?
}

struct NGSource: Decodable {
    var repo: String?
    var commit: String?
    var user: String?
    var installed_at: String?
}

struct NGReason: Decodable {
    var code: String?
    var text: String?
    var level: String?
    var why: String?
}

struct NGEvent: Decodable {
    var ts: Double?
    var type: String?
    var severity: String?
    var summary: String?
    var reasons: [NGReason]?
}

struct NGStatus: Decodable {
    var version: String?
    var updatedAt: Double?
    var wantedKillswitch: Bool?
    var killswitchComplete: Bool?
    var integrity: NGIntegrity?
    var claudeBlock: Bool?
    var realip: Bool?
    var dnsBlock: Bool?
    var guardInfo: NGGuard?
    var observations: NGObs?
    var whitelist: [String]?
    var requireClaudeguard: Bool?
    var requireGlobalMode: Bool?
    var interval: Double?
    var lastEvent: NGEvent?
    var source: NGSource?

    enum CodingKeys: String, CodingKey {
        case version, integrity, observations, whitelist, interval, realip, source
        case updatedAt = "updated_at"
        case wantedKillswitch = "wanted_killswitch"
        case killswitchComplete = "killswitch_complete"
        case claudeBlock = "claude_block"
        case dnsBlock = "dns_block"
        case guardInfo = "guard"
        case requireClaudeguard = "require_claudeguard"
        case requireGlobalMode = "require_global_mode"
        case lastEvent = "last_event"
    }
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

func modeName(_ m: String?) -> String {
    switch m {
    case "global": return "全局"
    case "rule": return "规则"
    case "direct": return "直连"
    default: return "待核实（读不到 FlClash 配置）"
    }
}

let eventNames: [String: String] = [
    "trigger": "触发保护", "suspect": "发现异常", "recovered": "已恢复", "release": "解除锁定",
    "release_refused": "解除被拒", "grace": "宽限暂缓", "config": "设置", "isolate": "隔离 Claude",
    "unisolate": "解除隔离", "rules_restored": "规则恢复", "rollback": "自动回滚", "recover": "紧急恢复",
    "kill": "结束 Claude", "guard_error": "检查出错", "info": "信息", "dns_relaxed": "放行局域网 DNS",
    "exempt": "放行身份被占用",
]

/// Quote for /bin/sh inside an AppleScript string literal.
func shellQuote(_ s: String) -> String {
    let sh = "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    return sh.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
}

final class Model: ObservableObject {
    @Published var status: NGStatus?
    @Published var decodeError: String?
    @Published var events: [NGEvent] = []
    @Published var busy = false
    private var timer: Timer?

    init() {
        reload()
        timer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.reload()
        }
    }

    func reload() {
        let decoder = JSONDecoder()
        if let data = FileManager.default.contents(atPath: ngRoot + "/status.json") {
            do {
                status = try decoder.decode(NGStatus.self, from: data)
                decodeError = nil
            } catch {
                status = nil
                decodeError = "status.json 无法解析：\(error)"
            }
        } else {
            status = nil
            decodeError = nil
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
        if s.realip == true { return .warn }
        if !(s.guardInfo?.last_findings ?? []).isEmpty { return .warn }
        return .ok
    }

    var headline: String {
        if let e = decodeError { return e }
        guard let s = status else { return "NetGuard 后台未运行（没有状态文件）" }
        if age >= 60 { return "状态已 \(Int(age)) 秒未更新：后台可能已停止" }
        if s.guardInfo?.lockdown == true { return "已锁定 Claude：" + (s.guardInfo?.reasons ?? []).joined(separator: "；") }
        if s.wantedKillswitch == true && s.killswitchComplete != true { return "断网保护不完整！" }
        if s.wantedKillswitch != true { return "断网保护未开启" }
        if s.realip == true { return "真实 IP 模式：Claude 已隔离" }
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
        adminShell(([ngCLI] + args).map { shellQuote($0) }.joined(separator: " "), done: done)
    }

    func adminShell(_ command: String, done: ((Bool, String) -> Void)? = nil) {
        runProcess("/usr/bin/osascript",
                   ["-e", "do shell script \"\(command) 2>&1\" with administrator privileges"], done: done)
    }

    /// Runs a program as the logged-in user (no administrator rights).
    func runProcess(_ exe: String, _ args: [String], done: ((Bool, String) -> Void)? = nil) {
        busy = true
        DispatchQueue.global().async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: exe)
            p.arguments = args
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
                text = "无法启动 \(exe)：\(error)"
            }
            if text.contains("User canceled") || text.contains("(-128)") { text = "已取消（未输入密码）。" }
            DispatchQueue.main.async { self.finish(ok, text.trimmingCharacters(in: .whitespacesAndNewlines), done) }
        }
    }

    private func finish(_ ok: Bool, _ text: String, _ done: ((Bool, String) -> Void)?) {
        busy = false
        reload()
        if let done = done { done(ok, text) } else { showResult(ok, text) }
    }

    var claudeguardCLI: String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        for p in [home + "/.local/bin/claudeguard", "/usr/local/bin/claudeguard"] where FileManager.default.isExecutableFile(atPath: p) {
            return p
        }
        return nil
    }

    func repairClaudeGuard() {
        guard let cg = claudeguardCLI else {
            showResult(false, "没有找到 claudeguard 命令（~/.local/bin/claudeguard）。请按 README 第 2 步安装 ClaudeGuard。")
            return
        }
        runProcess(cg, ["doctor"])
    }

    func update() {
        guard let repo = status?.source?.repo, FileManager.default.fileExists(atPath: repo + "/macos/install.sh") else {
            showResult(false, "找不到安装来源（/Library/NetGuard/source.json）。请在仓库目录运行 git pull 后重新运行 install.sh。")
            return
        }
        runProcess("/usr/bin/git", ["-C", repo, "pull", "--ff-only"]) { ok, text in
            if !ok {
                showResult(false, "git pull 失败（未改动已安装的程序）：\n" + text)
                return
            }
            if !confirm("安装更新？", "已拉取最新代码：\n\(text.suffix(400))\n\n接下来以管理员身份重新运行 install.sh（保留配置与状态，不改动断网规则）。") { return }
            self.adminShell("/bin/bash " + shellQuote(repo + "/macos/install.sh"))
        }
    }

    func uninstall() {
        if !confirm("卸载 NetGuard？", "会移除断网规则、后台、菜单栏程序和紧急恢复入口，配置与保护记录保留一份副本。卸载后代理断开时可能经真实 IP 联网。") { return }
        adminShell("/bin/bash /Library/NetGuard/uninstall.sh") { ok, text in
            showResult(ok, text)
            if ok { NSApp.terminate(nil) }
        }
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
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
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
            Text(label).foregroundColor(.secondary).frame(width: 96, alignment: .leading)
            if let ok = ok {
                Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(ok ? .green : .red)
            }
            Text(value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }
}

struct OverviewView: View {
    @ObservedObject var model: Model
    @Binding var showWizard: Bool

    var body: some View {
        let s = model.status
        let g = s?.guardInfo
        let o = s?.observations
        let i = s?.integrity
        let cg = o?.claudeguard
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: model.overall.symbol).font(.system(size: 34))
                            .foregroundColor(model.overall.swiftColor)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(model.headline).font(.title3).bold().fixedSize(horizontal: false, vertical: true)
                            Text("NetGuard \(s?.version ?? "?") · 上次检查 \(fmtTime(g?.last_check)) · 耗时 \(String(format: "%.1f", g?.duration ?? 0)) 秒")
                                .foregroundColor(.secondary).font(.caption)
                        }
                        Spacer()
                        VStack(alignment: .trailing) {
                            Text("当前出口").font(.caption).foregroundColor(.secondary)
                            Text(o?.egress ?? "未取得").font(.system(.title2, design: .monospaced)).bold()
                                .foregroundColor(o?.egress_ok == true ? .green : .red)
                        }
                    }
                    HStack(alignment: .top, spacing: 12) {
                        Card(title: "出口 IP") {
                            Line(label: "普通流量", value: o?.egress ?? "未取得", ok: o?.egress_ok)
                            Line(label: "claude.ai", value: o?.claude_egress ?? "未取得", ok: o?.claude_egress_ok)
                            Line(label: "白名单", value: (s?.whitelist ?? []).isEmpty ? "空" : (s?.whitelist ?? []).joined(separator: ", "))
                        }
                        Card(title: "自动防护") {
                            Line(label: "状态", value: g?.enabled == true ? "每 \(Int(s?.interval ?? 10)) 秒检查，连续 2 次异常即隔离 Claude" : "关闭")
                            Line(label: "锁定", value: g?.lockdown == true ? "是，\(fmtTime(g?.since)) 起" : "否", ok: g?.lockdown != true)
                            Line(label: "异常 / 原因", value: (g?.last_findings ?? []).isEmpty ? "无" : (g?.last_findings ?? []).joined(separator: "；"))
                            if let gu = g?.grace_until, gu > Date().timeIntervalSince1970 {
                                Line(label: "宽限期", value: "至 \(fmtTime(gu))（开机/登录/唤醒后中危不锁定）")
                            }
                            Line(label: "累计触发", value: "\(Int(g?.triggers ?? 0)) 次")
                        }
                    }
                    HStack(alignment: .top, spacing: 12) {
                        Card(title: "ClaudeGuard") {
                            if s?.requireClaudeguard == false {
                                Text("未要求（require_claudeguard=false）").foregroundColor(.secondary)
                            }
                            Line(label: "守护进程", value: cg?.fresh == true ? "运行中 / 保护\(cg?.protection_enabled == false ? "关闭" : "开启")" : "未运行或状态过期",
                                 ok: cg?.fresh == true && cg?.protection_enabled != false)
                            Line(label: "出口判定", value: "\(cg?.state ?? "?")  \(cg?.ip ?? "")", ok: cg?.state == "allowed")
                            Line(label: "网络助手", value: cg?.helper_loaded == true ? "运行中" : "未运行", ok: cg?.helper_loaded == true)
                            Line(label: "Claude 钩子", value: cg?.cli_hooked == nil ? "未安装 Claude Code（不适用）" : (cg?.cli_hooked == true ? "claude 命令经过 ClaudeGuard" : "claude 命令未经过 ClaudeGuard"),
                                 ok: cg?.cli_hooked == nil ? nil : cg?.cli_hooked == true)
                            Line(label: "桌面版", value: cg?.app_path_ok == nil ? "未安装（不适用）" : ((cg?.app_installed ?? []).joined(separator: "、") + (cg?.app_path_ok == true ? "，ClaudeGuard 已跟上" : "，ClaudeGuard 记录过期")),
                                 ok: cg?.app_path_ok)
                            Line(label: "Claude Code", value: cg?.cli_path_ok == nil ? "未安装（不适用）" : (cg?.cli_path_ok == true ? "ClaudeGuard 已跟上" : "ClaudeGuard 记录过期"),
                                 ok: cg?.cli_path_ok)
                        }
                        Card(title: "FlClash") {
                            Line(label: "进程", value: "界面 \(o?.flclash_ui == true ? "✓" : "✗") / 内核 \(o?.core?.running == true ? "✓" : "✗")",
                                 ok: o?.flclash_ui == true && o?.core?.running == true)
                            Line(label: "内核授权", value: o?.core?.privileged == true ? "root（TUN 已授权）" : "未授权", ok: o?.core?.privileged == true)
                            Line(label: "TUN 网卡", value: o?.tun ?? "未连接", ok: o?.tun != nil)
                            Line(label: "流量路由", value: o?.route == nil ? "?" : (o?.route == o?.tun ? "经过 TUN（\(o?.route ?? "")）" : "未经过 TUN（\(o?.route ?? "")）"),
                                 ok: o?.tun != nil && o?.route == o?.tun)
                            Line(label: "代理模式", value: modeName(o?.flclash?.mode),
                                 ok: s?.requireGlobalMode == true ? o?.flclash?.mode == "global" : nil)
                            Line(label: "严格路由", value: "由 NetGuard pf 规则承担（macOS 无需 strict-route）")
                        }
                    }
                    Card(title: "断网保护（NetGuard）") {
                        Line(label: "规则", value: s?.wantedKillswitch == true ? (s?.killswitchComplete == true ? "已开启 / \(Int(i?.rule_count ?? 0)) 条规则完整" : "已开启但不完整") : "未开启",
                             ok: s?.wantedKillswitch == true ? s?.killswitchComplete == true : nil)
                        Line(label: "pf / token", value: "\(i?.pf_enabled == true ? "已启用" : "未启用") / 锚点引用\(i?.main_anchor_ref == true ? "存在" : "缺失") / token \(i?.token_live == true ? "有效" : "无")")
                        Line(label: "局域网 DNS", value: s?.dnsBlock == true ? "拦截（与 Windows 相同）" : "放行（系统 DNS 是路由器时自动放行）")
                        Line(label: "Claude 隔离", value: s?.claudeBlock == true ? "已隔离（打开会被立即结束，Anthropic 网段连 TUN 也拦）" : "未隔离")
                        Line(label: "真实 IP 模式", value: s?.realip == true ? "已启用" : "未启用")
                        if let others = o?.exempt_others, !others.isEmpty {
                            Line(label: "注意", value: others.joined(separator: "、") + " 与代理内核共用放行身份联网", ok: false)
                        }
                        Line(label: "最近操作", value: "\(fmtTime(s?.lastEvent?.ts)) [\(eventNames[s?.lastEvent?.type ?? ""] ?? (s?.lastEvent?.type ?? "—"))] \(s?.lastEvent?.summary ?? "")")
                        Line(label: "FlClash 配置", value: "\(o?.flclash?.path ?? "未找到")（\(fmtTime(o?.flclash?.mtime))）")
                    }
                    Text("界面绿色只表示当前检查通过；真实停代理、睡眠唤醒、切换网络需另行验收。")
                        .font(.caption).foregroundColor(.secondary)
                }
                .padding(16)
            }
            Divider()
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
                Button(s?.realip == true ? "退出真实 IP 模式…" : "进入真实 IP 模式…") { showWizard = true }
                Button("解除锁定") { model.admin(["release"]) }.disabled(g?.lockdown != true)
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Button("刷新检测") { model.admin(["refresh"]) }.keyboardShortcut("r")
            }
            .padding(12)
        }
    }
}

struct RealIpWizard: View {
    @ObservedObject var model: Model
    @Binding var isPresented: Bool
    var body: some View {
        let s = model.status
        let o = s?.observations
        let inMode = s?.claudeBlock == true
        VStack(alignment: .leading, spacing: 12) {
            Text("真实 IP 模式").font(.title2).bold()
            Text("需要暂时不用代理时使用：先隔离 Claude，再改代理；出口回到白名单后再退出。锁定期间请用“解除锁定”，不要用这里。")
                .foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            GroupBox("① 隔离 Claude") {
                HStack {
                    Text(inMode ? "Claude 已隔离：打开会在半秒内被结束，Anthropic 网段连 TUN 也被拦截。" : "结束 Claude 桌面版和 Claude Code，之后打开也会被结束。")
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("隔离 Claude") { model.admin(["isolate"]) }.disabled(inMode)
                }.padding(6)
            }
            GroupBox("② 处理你的事情") {
                Text("现在可以在 FlClash 里切换模式或关闭代理。注意：断网保护仍在，若关闭了它，代理断开时其他程序会走真实 IP。完成后把 FlClash 恢复为正常节点、全局模式、TUN 开启。")
                    .fixedSize(horizontal: false, vertical: true).padding(6)
            }
            GroupBox("③ 核对出口并退出") {
                VStack(alignment: .leading) {
                    Line(label: "普通出口", value: o?.egress ?? "未取得", ok: o?.egress_ok)
                    Line(label: "claude.ai", value: o?.claude_egress ?? "未取得", ok: o?.claude_egress_ok)
                    HStack {
                        Spacer()
                        Button("核对并退出真实 IP 模式") { model.admin(["unisolate"]) }
                            .disabled(!inMode || s?.guardInfo?.lockdown == true)
                    }
                }.padding(6)
            }
            HStack {
                if model.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("关闭") { isPresented = false }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}

struct RecordsView: View {
    @ObservedObject var model: Model
    @State private var onlyImportant = false
    var body: some View {
        VStack(alignment: .leading) {
            Toggle("只看触发 / 解除 / 回滚 / 恢复 / 设置", isOn: $onlyImportant).padding([.top, .horizontal])
            List {
                ForEach(Array(filtered.enumerated()), id: \.offset) { _, e in
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(alignment: .firstTextBaseline) {
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
        let keep: Set<String> = ["trigger", "release", "release_refused", "rollback", "recover", "rules_restored",
                                 "config", "dns_relaxed", "exempt", "isolate", "unisolate"]
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
                        Button("添加") {
                            model.admin(["whitelist", "add", newIP.trimmingCharacters(in: .whitespaces)]) { ok, text in
                                if ok { newIP = "" }
                                showResult(ok, text)
                            }
                        }.disabled(newIP.trimmingCharacters(in: .whitespaces).isEmpty)
                        Button("从 ClaudeGuard 导入") { model.admin(["whitelist", "import-claudeguard"]) }
                    }
                }
                Card(title: "自动防护") {
                    HStack {
                        if model.status?.guardInfo?.enabled == true {
                            Button("关闭自动防护") {
                                if confirm("关闭自动防护？", "不影响断网保护规则和现有锁定，但不再自动锁定 Claude。") { model.admin(["guard-off"]) }
                            }
                        } else {
                            Button("开启自动防护") { model.admin(["guard-on"]) }
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
                Card(title: "ClaudeGuard") {
                    HStack {
                        Button("修复 ClaudeGuard（claudeguard doctor）") { model.repairClaudeGuard() }
                    }
                    Text("重新挂上 claude 命令和桌面版的钩子；Claude 更新后若显示“钩子未经过 ClaudeGuard”时使用。")
                        .font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Card(title: "安装与更新") {
                    let src = model.status?.source
                    Line(label: "安装来源", value: "\(src?.repo ?? "未记录") @ \(src?.commit ?? "?")（\(src?.installed_at ?? "?")）")
                    HStack {
                        Button("更新 NetGuard（git pull + 重新安装）") { model.update() }
                        Button("卸载 NetGuard…") { model.uninstall() }
                    }
                }
                Card(title: "文件与急救") {
                    HStack {
                        Button("打开 NetGuard 目录") { NSWorkspace.shared.open(URL(fileURLWithPath: ngRoot)) }
                        Button("打开日志") { NSWorkspace.shared.open(URL(fileURLWithPath: ngRoot + "/netguard.log")) }
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
    @State private var showWizard = false
    var body: some View {
        TabView {
            OverviewView(model: model, showWizard: $showWizard).tabItem { Text("概览") }
            RecordsView(model: model).tabItem { Text("保护记录") }
            MaintenanceView(model: model).tabItem { Text("维护") }
        }
        .frame(minWidth: 760, minHeight: 640)
        .sheet(isPresented: $showWizard) { RealIpWizard(model: model, isPresented: $showWizard) }
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
            "内核：\(o?.core?.running == true ? (o?.core?.privileged == true ? "已授权" : "未授权") : "未运行")   TUN：\(o?.tun ?? "未连接")   模式：\(modeName(o?.flclash?.mode))",
        ] {
            let i = NSMenuItem(title: line, action: nil, keyEquivalent: "")
            i.isEnabled = false
            menu.addItem(i)
        }
        menu.addItem(.separator())
        menu.addItem(withTitle: "打开工作台…", action: #selector(openWorkbench), keyEquivalent: "w").target = self
        if s?.wantedKillswitch == true {
            menu.addItem(withTitle: "关闭断网保护…", action: #selector(disableKillswitch), keyEquivalent: "").target = self
        } else {
            menu.addItem(withTitle: "开启断网保护…", action: #selector(enableKillswitch), keyEquivalent: "").target = self
        }
        if s?.guardInfo?.lockdown == true {
            menu.addItem(withTitle: "解除锁定…", action: #selector(releaseLockdown), keyEquivalent: "").target = self
        }
        menu.addItem(withTitle: "刷新检测…", action: #selector(refreshNow), keyEquivalent: "r").target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "紧急恢复（移除断网规则）…", action: #selector(recoverNow), keyEquivalent: "").target = self
        menu.addItem(withTitle: "退出菜单栏图标", action: #selector(quitApp), keyEquivalent: "q").target = self
    }

    @objc func openWorkbench() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 860, height: 760),
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

    @objc func enableKillswitch() {
        if confirm("开启断网保护？", "会先预检，加载规则后自检；任一失败会自动恢复，不会让你断网。建议先关闭浏览器和 Claude。") {
            model.admin(["enable"])
        }
    }
    @objc func disableKillswitch() {
        if confirm("关闭断网保护？", "关闭后代理一旦断开，流量可能经真实 IP 发出；同时会解除锁定与隔离（不做检查）。") {
            model.admin(["disable"])
        }
    }
    @objc func releaseLockdown() { model.admin(["release"]) }
    @objc func refreshNow() { model.admin(["refresh"]) }
    @objc func recoverNow() {
        if confirm("执行紧急恢复？", "会移除 NetGuard 的全部 pf 规则并关闭断网保护。") {
            NSWorkspace.shared.open(URL(fileURLWithPath: recoverCommand))
        }
    }
    @objc func quitApp() { NSApp.terminate(nil) }
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
