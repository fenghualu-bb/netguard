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
    var reason_codes: [String]?
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
    var cg_patch: String?
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
    var proxy_up: Bool?
    var proxy_down_direct: Bool?
}

struct NGClaudeProc: Decodable {
    var pid: Double?
    var name: String?
    var role: String?
    var origin: String?
    var path: String?
}

struct NGCleanup: Decodable {
    var at: Double?
    var cleaned: [NGClaudeProc]?
    var failed: [NGClaudeProc]?
}

struct NGClaude: Decodable {
    var main_running: Bool?
    var count: Double?
    var processes: [NGClaudeProc]?
    var policy: String?
    var cleaning: Double?
    var checked_at: Double?
    var last_cleanup: NGCleanup?
}

struct NGUpdateStep: Decodable {
    var action: String?
    var note: String?
    var commit: String?
    var version: String?
}

struct NGUpdateLast: Decodable {
    var netguard: NGUpdateStep?
    var claudeguard: NGUpdateStep?
}

struct NGUpdate: Decodable {
    var enabled: Bool?
    var installed: String?
    var last_check: Double?
    var soak_hours: Double?
    var last: NGUpdateLast?
    var claudeguard_installed: String?
}

struct NGDirectCheck: Decodable {
    var at: Double?
    var via: String?
    var moved: [String]?
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
    var claude: NGClaude?
    var proxyDown: String?
    var direct: Bool?
    var directBlock: Double?
    var directCheck: NGDirectCheck?
    var update: NGUpdate?

    enum CodingKeys: String, CodingKey {
        case version, integrity, observations, whitelist, interval, realip, source, claude, direct, update
        case proxyDown = "proxy_down"
        case directBlock = "direct_block"
        case directCheck = "direct_check"
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
    "exempt": "放行身份被占用", "cleanup": "清理 Claude 残留", "anthropic_moved": "主站地址变化",
]

let roleNames: [String: String] = [
    "main": "桌面版", "helper": "辅助进程", "updater": "更新程序", "cli": "Claude Code", "descendant": "子进程",
]

let cleanupNames: [String: String] = [
    "full": "清理残留，并结束单独运行的 Claude Code", "desktop": "只清理桌面版的残留", "off": "不清理",
]

/// "Claude Helper ×3、zsh ×2"
func summarizeNames(_ procs: [NGClaudeProc]) -> String {
    var counts: [String: Int] = [:]
    var order: [String] = []
    for p in procs {
        let n = p.name ?? "?"
        if counts[n] == nil { order.append(n) }
        counts[n, default: 0] += 1
    }
    return order.sorted { counts[$0]! > counts[$1]! }
        .map { counts[$0]! > 1 ? "\($0) ×\(counts[$0]!)" : $0 }.joined(separator: "、")
}

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
    /// Last cleanup already shown, so a restart of the menu app never replays an old alert.
    private var lastCleanupSeen = UserDefaults.standard.double(forKey: "lastCleanupSeen")

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
                announceCleanup()
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

    /// On-screen alert after a cleanup (from ClaudeExitGuard): no notification permission needed.
    private func announceCleanup() {
        guard let c = status?.claude?.last_cleanup, let at = c.at, at > lastCleanupSeen else { return }
        let fresh = Date().timeIntervalSince1970 - at < 60
        lastCleanupSeen = at
        UserDefaults.standard.set(at, forKey: "lastCleanupSeen")
        if fresh { showCleanupPanel(c) }
    }

    /// Direct mode with the proxy off: Claude is isolated on purpose and lifts itself later.
    var proxyOffIsolation: Bool {
        guard let g = status?.guardInfo, g.lockdown == true else { return false }
        let codes = Set(g.reason_codes ?? [])
        return codes.contains("proxy_down") && codes.isSubset(of: ["proxy_down", "core", "tun"])
    }

    var age: Double {
        guard let u = status?.updatedAt else { return .infinity }
        return Date().timeIntervalSince1970 - u
    }

    var overall: Overall {
        guard let s = status, age < 60 else { return .stale }
        if proxyOffIsolation { return .warn }
        if s.guardInfo?.lockdown == true { return .bad }
        if s.wantedKillswitch == true && s.killswitchComplete != true { return .bad }
        if s.wantedKillswitch != true { return .off }
        if s.realip == true { return .warn }
        if !(s.guardInfo?.last_findings ?? []).isEmpty { return .warn }
        if s.observations?.egress_ok != true || s.observations?.claude_egress_ok != true { return .warn }
        return .ok
    }

    var headline: String {
        if let e = decodeError { return e }
        guard let s = status else { return "NetGuard 后台未运行（没有状态文件）" }
        if age >= 60 { return "状态已 \(Int(age)) 秒未更新：后台可能已停止" }
        if proxyOffIsolation { return "代理已断开：Claude 已隔离，其他程序可直连" }
        if s.guardInfo?.lockdown == true, let reasons = s.guardInfo?.reasons, let first = reasons.first {
            return "已锁定 Claude：" + first + (reasons.count > 1 ? "（等 \(reasons.count) 项）" : "")
        }
        if s.guardInfo?.lockdown == true { return "已锁定 Claude：" + (s.guardInfo?.reasons ?? []).joined(separator: "；") }
        if s.wantedKillswitch == true && s.killswitchComplete != true { return "断网保护不完整！" }
        if s.wantedKillswitch != true { return "断网保护未开启" }
        if s.realip == true { return "真实 IP 模式：Claude 已隔离" }
        let f = s.guardInfo?.last_findings ?? []
        if !f.isEmpty { return "有异常：" + f.joined(separator: "；") }
        if s.observations?.egress_ok != true || s.observations?.claude_egress_ok != true {
            return "出口待核实：探测未通过，不能据此判定整机断网"
        }
        return "当前检查通过（未做断线测试）"
    }

    // NETGUARD_LOCAL_RELEASE_V1
    /// The local root helper accepts only release and retains all original checks.
    func releaseWithoutPassword() {
        runProcess("/Library/NetGuard/bin/netguard-control", ["release"])
    }

    /// Refresh reads the latest state; the background continues checking every 10 s.
    func refreshStatus() { reload() }

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

    /// Applies NetGuard's hash-checked ClaudeGuard compatibility patch, then `claudeguard doctor`.
    func repairClaudeGuard() {
        guard claudeguardCLI != nil else {
            showResult(false, "没有找到 claudeguard 命令（~/.local/bin/claudeguard）。请按 README 第 2 步安装 ClaudeGuard。")
            return
        }
        runProcess("/bin/bash", ["/Library/NetGuard/bin/claudeguard-patch"])
    }

    /// Runs the root updater now (CI must still have passed; only the 24-hour wait is skipped).
    func update() {
        if confirm("立即检查并更新 NetGuard？", "只会安装 main 上 CI 全部通过的版本（跳过 24 小时等待）。安装后自动自检，失败会自动恢复原版本。") {
            admin(["update", "now"])
        }
    }

    var updateText: String {
        guard let u = status?.update else { return "自动更新尚未运行" }
        var parts: [String] = [u.enabled == false ? "已关闭" : "每 6 小时检查一次，只装 main 上满 \(Int(u.soak_hours ?? 24)) 小时且 CI 全过的版本"]
        if let n = u.last?.netguard {
            parts.append("上次（\(fmtTime(u.last_check))）：" + (n.note ?? n.action ?? ""))
        }
        if let c = u.last?.claudeguard, let note = c.note, c.action != "off" {
            parts.append("ClaudeGuard：" + note)
        }
        return parts.joined(separator: "；")
    }

    func uninstall() {
        if !confirm("卸载 NetGuard？", "会移除断网规则、后台、菜单栏程序和紧急恢复入口，配置与保护记录保留一份副本。卸载后代理断开时可能经真实 IP 联网。") { return }
        adminShell("/bin/bash /Library/NetGuard/uninstall.sh") { ok, text in
            showResult(ok, text)
            if ok { NSApp.terminate(nil) }
        }
    }
}

var cleanupPanel: NSPanel?

/// A floating panel for about 12 seconds with a sound, like ClaudeExitGuard's alert.
func showCleanupPanel(_ c: NGCleanup) {
    let cleaned = c.cleaned ?? []
    let failed = c.failed ?? []
    let title = failed.isEmpty ? "Claude 已退出：结束了 \(cleaned.count) 个残留进程"
                               : "有 \(failed.count) 个 Claude 残留进程未能结束"
    var detail = cleaned.isEmpty ? "" : summarizeNames(cleaned)
    if !failed.isEmpty { detail += (detail.isEmpty ? "" : "\n") + "未能结束：" + summarizeNames(failed) }
    cleanupPanel?.close()
    let panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 400, height: 96),
                        styleMask: [.titled, .closable, .nonactivatingPanel, .utilityWindow],
                        backing: .buffered, defer: false)
    panel.title = "NetGuard"
    panel.level = .floating
    panel.isReleasedWhenClosed = false
    panel.hidesOnDeactivate = false
    panel.contentView = NSHostingView(rootView:
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: failed.isEmpty ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 26)).foregroundColor(failed.isEmpty ? .green : .orange)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(detail).font(.caption).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }.padding(12).frame(width: 400))
    if let screen = NSScreen.main?.visibleFrame {
        panel.setFrameTopLeftPoint(NSPoint(x: screen.maxX - 420, y: screen.maxY - 12))
    }
    panel.orderFrontRegardless()
    NSSound(named: failed.isEmpty ? "Glass" : "Basso")?.play()
    cleanupPanel = panel
    DispatchQueue.main.asyncAfter(deadline: .now() + 12) { [weak panel] in
        if cleanupPanel === panel { panel?.close() }
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

/// One meaning per color everywhere: green = fine, orange = needs a look, red = act, gray = not applicable.
enum Tone {
    case ok, warn, bad, neutral

    var color: Color {
        switch self {
        case .ok: return .green
        case .warn: return .orange
        case .bad: return .red
        case .neutral: return .secondary
        }
    }
    var symbol: String {
        switch self {
        case .ok: return "checkmark.circle.fill"
        case .warn: return "exclamationmark.circle.fill"
        case .bad: return "xmark.circle.fill"
        case .neutral: return "minus.circle"
        }
    }
}

func tone(_ ok: Bool?) -> Tone { ok == nil ? .neutral : (ok! ? .ok : .bad) }

/// Numbers without thousands separators (a pid is not "15,926").
func plain(_ v: Double?) -> String { String(Int(v ?? 0)) }

/// ClaudeGuard's verdict in words: "blocked" is ClaudeGuard doing its job, not a failure.
func cgStateName(_ state: String?) -> String {
    switch state {
    case "allowed": return "放行 Claude"
    case "blocked": return "已拦截 Claude"
    case nil: return "?"
    default: return state!
    }
}

let panelFill = Color(nsColor: .controlBackgroundColor)
let panelStroke = Color(nsColor: .separatorColor).opacity(0.6)

struct Panel<Content: View>: View {
    var padding: CGFloat = 14
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 8) { content }
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 10).fill(panelFill))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(panelStroke, lineWidth: 0.5))
    }
}

/// Kept for older call sites (the real-IP wizard).
struct Card<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        Panel {
            Text(title).font(.headline)
            content
        }
    }
}

/// A label / value row; labels share one column width so values line up.
struct Line: View {
    let label: String
    let value: String
    var ok: Bool? = nil
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label).foregroundStyle(.secondary).frame(width: 92, alignment: .leading)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                if let ok = ok {
                    Image(systemName: tone(ok).symbol).foregroundStyle(tone(ok).color).font(.callout)
                }
                Text(value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .font(.callout)
    }
}

// MARK: Overview

struct StatusBanner: View {
    @ObservedObject var model: Model
    var body: some View {
        let s = model.status
        let g = s?.guardInfo
        let o = s?.observations
        let color = model.overall.swiftColor
        let proxyOff = o?.proxy_down_direct == true
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: model.overall.symbol)
                .font(.system(size: 36, weight: .medium))
                .foregroundStyle(color)
                .frame(width: 44)
            VStack(alignment: .leading, spacing: 4) {
                Text(model.headline).font(.title3.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                Text("上次检查 \(fmtTime(g?.last_check)) · 用时 \(String(format: "%.1f", g?.duration ?? 0)) 秒 · NetGuard \(s?.version ?? "?")")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 12)
            VStack(alignment: .trailing, spacing: 2) {
                Text(proxyOff ? "代理" : "当前出口").font(.caption).foregroundStyle(.secondary)
                Text(proxyOff ? "已断开" : (o?.egress ?? "未取得"))
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .foregroundStyle(proxyOff ? Color.orange : (o?.egress_ok == true ? Color.green : Color.red))
                    .textSelection(.enabled)
            }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: 12).fill(color.opacity(0.10)))
        .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(color.opacity(0.35), lineWidth: 1))
    }
}

struct ChainTile: View {
    let icon: String
    let title: String
    let value: String
    let detail: String
    let tone: Tone
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon).foregroundStyle(.secondary)
                Text(title).font(.subheadline).foregroundStyle(.secondary)
                Spacer(minLength: 0)
                Image(systemName: tone.symbol).foregroundStyle(tone.color)
            }
            Text(value).font(.headline).lineLimit(1).minimumScaleFactor(0.75)
            Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 96, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 10).fill(panelFill))
        .overlay(RoundedRectangle(cornerRadius: 10)
            .strokeBorder(tone == .ok || tone == .neutral ? panelStroke : tone.color.opacity(0.6),
                          lineWidth: tone == .ok || tone == .neutral ? 0.5 : 1.2))
    }
}

/// A collapsible section: a one-line summary when closed, aligned rows when open.
struct DetailSection<Content: View>: View {
    let icon: String
    let title: String
    let summary: String
    var summaryTone: Tone = .neutral
    @Binding var expanded: Bool
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { expanded.toggle() }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                    Image(systemName: icon).foregroundStyle(.secondary).frame(width: 18)
                    Text(title).font(.headline)
                    Spacer(minLength: 12)
                    if summaryTone != .neutral {
                        Image(systemName: summaryTone.symbol).foregroundStyle(summaryTone.color).font(.callout)
                    }
                    Text(summary).font(.callout).foregroundStyle(.secondary).lineLimit(1)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 14).padding(.vertical, 11)
            if expanded {
                Divider().padding(.horizontal, 14)
                VStack(alignment: .leading, spacing: 7) { content }
                    .padding(.horizontal, 14).padding(.top, 10).padding(.bottom, 14)
            }
        }
        .background(RoundedRectangle(cornerRadius: 10).fill(panelFill))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(panelStroke, lineWidth: 0.5))
    }
}

let roleOrder: [String: Int] = ["main": 0, "helper": 1, "updater": 2, "cli": 3, "descendant": 4]

struct ProcessTable: View {
    let procs: [NGClaudeProc]
    var body: some View {
        let rows = procs.sorted {
            let a = roleOrder[$0.role ?? ""] ?? 9, b = roleOrder[$1.role ?? ""] ?? 9
            return a != b ? a < b : ($0.pid ?? 0) < ($1.pid ?? 0)
        }
        Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 5) {
            GridRow {
                Text("PID").gridColumnAlignment(.trailing)
                Text("类型")
                Text("程序")
                Text("路径")
            }
            .font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            Divider().gridCellUnsizedAxes(.horizontal)
            ForEach(Array(rows.enumerated()), id: \.offset) { _, p in
                GridRow(alignment: .firstTextBaseline) {
                    Text(plain(p.pid)).font(.system(.caption, design: .monospaced))
                    Text(roleNames[p.role ?? ""] ?? (p.role ?? ""))
                        .font(.caption2.weight(.medium))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                    Text(p.name ?? "?").font(.caption).lineLimit(1)
                    Text(p.path ?? "").font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle).help(p.path ?? "")
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .textSelection(.enabled)
    }
}

struct OverviewView: View {
    @ObservedObject var model: Model
    @Binding var showWizard: Bool
    @AppStorage("ov.exit") private var openExit = false
    @AppStorage("ov.rules") private var openRules = false
    @AppStorage("ov.cg") private var openCG = false
    @AppStorage("ov.claude") private var openClaude = false

    var body: some View {
        let s = model.status
        let g = s?.guardInfo
        let o = s?.observations
        let i = s?.integrity
        let cg = o?.claudeguard
        let c = s?.claude
        let direct = s?.proxyDown == "direct"
        let proxyOff = o?.proxy_down_direct == true
        let proxyOK = o?.core?.privileged == true && o?.tun != nil && o?.route == o?.tun
        // Same rule as the daemon: only a mode read as rule/direct is wrong; unreadable is "待核实".
        let modeOK = s?.requireGlobalMode != true || !["rule", "direct"].contains(o?.flclash?.mode ?? "")
        let exitOK = o?.egress_ok == true && o?.claude_egress_ok == true
        let rulesOK = s?.wantedKillswitch == true && s?.killswitchComplete == true
        let cgOK = cg?.fresh == true && cg?.protection_enabled != false && cg?.helper_loaded == true
            && cg?.cli_hooked != false && cg?.app_path_ok != false && cg?.cli_path_ok != false
        let isolated = s?.claudeBlock == true
        let attention = attentionItems(s)

        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    StatusBanner(model: model)

                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 10)], spacing: 10) {
                        ChainTile(icon: "network", title: "代理",
                                  value: proxyOff ? "已断开" : (proxyOK ? "TUN \(o?.tun ?? "")" : "未就绪"),
                                  detail: proxyOff ? "直连模式：其他程序用真实 IP" : "FlClash \(modeName(o?.flclash?.mode))模式",
                                  tone: proxyOff ? .warn : (proxyOK && modeOK ? .ok : .bad))
                        ChainTile(icon: "globe", title: "出口",
                                  value: proxyOff ? "不探测" : (o?.egress ?? "未取得"),
                                  detail: proxyOff ? "代理断开时不探测真实出口" : (exitOK ? "两个出口都在白名单" : "出口不在白名单或未取得"),
                                  tone: proxyOff ? .neutral : (exitOK ? .ok : .bad))
                        ChainTile(icon: "lock.shield", title: "断网保护",
                                  value: s?.wantedKillswitch == true ? (rulesOK ? "已开启" : "不完整") : "未开启",
                                  detail: direct ? "代理断开时允许直连" : "代理断开时整机断网",
                                  tone: s?.wantedKillswitch == true ? (rulesOK ? .ok : .bad) : .warn)
                        ChainTile(icon: "checkmark.seal", title: "ClaudeGuard",
                                  value: cg?.fresh == true ? cgStateName(cg?.state) : "未运行",
                                  detail: cgOK ? "保护、助手、钩子都正常" : "有一项未就绪，展开下方查看",
                                  tone: s?.requireClaudeguard == false ? .neutral : (cgOK ? .ok : .bad))
                        ChainTile(icon: "sparkle", title: "Claude",
                                  value: isolated ? "已隔离" : (c?.main_running == true ? "运行中" : "未运行"),
                                  detail: isolated ? "打开会被立即结束" : "相关进程 \(plain(c?.count)) 个",
                                  tone: isolated ? .warn : .ok)
                    }

                    if !attention.isEmpty {
                        Panel {
                            Label("需要注意", systemImage: "exclamationmark.triangle.fill")
                                .font(.headline).foregroundStyle(model.overall == .bad ? Color.red : Color.orange)
                            ForEach(Array(attention.enumerated()), id: \.offset) { _, item in
                                HStack(alignment: .firstTextBaseline, spacing: 8) {
                                    Text("•").foregroundStyle(.secondary)
                                    Text(item).font(.callout).fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                    }

                    DetailSection(icon: "arrow.left.arrow.right", title: "出口与代理",
                                  summary: proxyOff ? "代理已断开" : "\(o?.egress ?? "未取得") · \(modeName(o?.flclash?.mode))",
                                  summaryTone: proxyOff ? .warn : (exitOK && proxyOK && modeOK ? .ok : .bad), expanded: $openExit) {
                        if proxyOff {
                            Line(label: "普通流量", value: "代理已断开，其他程序直连（不探测真实出口）")
                            Line(label: "claude.ai", value: "Claude 已隔离，Anthropic 网段只能经代理访问")
                        } else {
                            Line(label: "普通流量", value: o?.egress ?? "未取得", ok: o?.egress_ok)
                            Line(label: "claude.ai", value: o?.claude_egress ?? "未取得", ok: o?.claude_egress_ok)
                        }
                        Line(label: "白名单", value: (s?.whitelist ?? []).isEmpty ? "空" : (s?.whitelist ?? []).joined(separator: "、"))
                        Divider()
                        Line(label: "FlClash", value: "界面\(o?.flclash_ui == true ? "运行中" : "未运行") · 内核\(o?.core?.running == true ? (o?.core?.privileged == true ? "已授权（root）" : "未授权") : "未运行")",
                             ok: o?.core?.privileged == true)
                        Line(label: "TUN 网卡", value: o?.tun ?? "未连接", ok: proxyOff ? nil : o?.tun != nil)
                        Line(label: "流量路由", value: o?.route == nil ? "未知" : (o?.route == o?.tun ? "经过 TUN（\(o?.route ?? "")）" : "未经过 TUN（\(o?.route ?? "")）"),
                             ok: proxyOff ? nil : o?.tun != nil && o?.route == o?.tun)
                        Line(label: "代理模式", value: modeName(o?.flclash?.mode),
                             ok: s?.requireGlobalMode == true && o?.flclash?.mode != nil ? o?.flclash?.mode == "global" : nil)
                        Line(label: "配置文件", value: "\(o?.flclash?.path ?? "未找到")（\(fmtTime(o?.flclash?.mtime))）")
                    }

                    DetailSection(icon: "lock.shield", title: "断网保护",
                                  summary: s?.wantedKillswitch == true ? "\(plain(i?.rule_count)) 条规则 · \(direct ? "代理断开时允许直连" : "代理断开时整机断网")" : "未开启",
                                  summaryTone: s?.wantedKillswitch == true ? (rulesOK ? .ok : .bad) : .warn, expanded: $openRules) {
                        Line(label: "规则", value: s?.wantedKillswitch == true ? (rulesOK ? "已开启，\(plain(i?.rule_count)) 条规则完整" : "已开启但不完整") : "未开启",
                             ok: s?.wantedKillswitch == true ? rulesOK : nil)
                        Line(label: "pf", value: "\(i?.pf_enabled == true ? "已启用" : "未启用") · 锚点引用\(i?.main_anchor_ref == true ? "存在" : "缺失") · token \(i?.token_live == true ? "有效" : "无")")
                        Line(label: "代理断开时", value: direct ? "允许直连：浏览器等用真实 IP，Claude 立即隔离，恢复后自动解除" : "整机断网：只剩局域网")
                        if direct {
                            let check = s?.directCheck
                            Line(label: "拦截表", value: "Claude 的其他地址 \(plain(s?.directBlock)) 个（只能经代理访问）")
                            Line(label: "主站网段", value: check == nil ? "尚未核对" : ((check?.moved ?? []).isEmpty ? "在 Anthropic 网段内（\(fmtTime(check?.at)) 核对）" : "不在官方网段：" + (check?.moved ?? []).joined(separator: "、")),
                                 ok: check == nil ? nil : (check?.moved ?? []).isEmpty)
                        } else {
                            Line(label: "局域网 DNS", value: s?.dnsBlock == true ? "拦截" : "放行（系统 DNS 是路由器时自动放行）")
                        }
                        Line(label: "Claude 隔离", value: isolated ? "已隔离：打开会被立即结束，Anthropic 网段连 TUN 也拦" : "未隔离")
                        Line(label: "真实 IP 模式", value: s?.realip == true ? "已启用" : "未启用")
                        Line(label: "累计触发", value: "\(plain(g?.triggers)) 次")
                        Line(label: "最近操作", value: "\(fmtTime(s?.lastEvent?.ts)) \(eventNames[s?.lastEvent?.type ?? ""] ?? (s?.lastEvent?.type ?? "—"))：\(s?.lastEvent?.summary ?? "")")
                    }

                    DetailSection(icon: "checkmark.seal", title: "ClaudeGuard",
                                  summary: cg?.fresh == true ? "运行中 · \(cgStateName(cg?.state))" : "未运行或状态过期",
                                  summaryTone: s?.requireClaudeguard == false ? .neutral : (cgOK ? .ok : .bad), expanded: $openCG) {
                        Line(label: "守护进程", value: cg?.fresh == true ? "运行中，保护\(cg?.protection_enabled == false ? "关闭" : "开启")" : "未运行或状态过期",
                             ok: cg?.fresh == true && cg?.protection_enabled != false)
                        Line(label: "出口判定", value: "\(cgStateName(cg?.state))（看到的出口 \(cg?.ip ?? "?")）", ok: cg?.state == "allowed")
                        Line(label: "网络助手", value: cg?.helper_loaded == true ? "运行中" : "未运行", ok: cg?.helper_loaded == true)
                        Line(label: "claude 命令", value: cg?.cli_hooked == nil ? "未安装 Claude Code" : (cg?.cli_hooked == true ? "经过 ClaudeGuard" : "未经过 ClaudeGuard"),
                             ok: cg?.cli_hooked)
                        Line(label: "桌面版", value: cg?.app_path_ok == nil ? "未安装" : (cg?.app_path_ok == true ? "ClaudeGuard 已跟上" : "ClaudeGuard 记录过期"), ok: cg?.app_path_ok)
                        Line(label: "Claude Code", value: cg?.cli_path_ok == nil ? "未安装" : (cg?.cli_path_ok == true ? "ClaudeGuard 已跟上" : "记录过期（维护页“修复 ClaudeGuard”）"), ok: cg?.cli_path_ok)
                        Line(label: "兼容补丁", value: cg?.cg_patch == "patched" ? "已应用" : (cg?.cg_patch == "original" ? "未应用" : (cg?.cg_patch == nil ? "—" : "未知版本")),
                             ok: cg?.cg_patch == nil ? nil : cg?.cg_patch == "patched")
                    }

                    DetailSection(icon: "sparkle", title: "Claude 进程",
                                  summary: "\(c?.main_running == true ? "桌面版运行中" : "桌面版未运行") · \(plain(c?.count)) 个相关进程",
                                  expanded: $openClaude) {
                        Line(label: "退出后清理", value: cleanupNames[c?.policy ?? ""] ?? "—")
                        if let last = c?.last_cleanup {
                            Line(label: "上次清理", value: "\(fmtTime(last.at))，结束 \((last.cleaned ?? []).count) 个" + ((last.failed ?? []).isEmpty ? "" : "，\((last.failed ?? []).count) 个未能结束"),
                                 ok: (last.failed ?? []).isEmpty)
                        }
                        if let procs = c?.processes, !procs.isEmpty {
                            Divider().padding(.vertical, 2)
                            ProcessTable(procs: procs)
                        }
                    }

                    Text("绿色只表示当前检查通过；停代理、睡眠唤醒、切换网络需按验收清单在真机上验证。")
                        .font(.caption).foregroundStyle(.secondary).padding(.horizontal, 2)
                }
                .padding(16)
            }
            Divider()
            HStack(spacing: 8) {
                if s?.wantedKillswitch == true {
                    Button("关闭断网保护") {
                        if confirm("关闭断网保护？", "关闭后代理一旦断开，流量可能经真实 IP 发出；同时会解除 Claude 的锁定与隔离（不做检查）。") {
                            model.admin(["disable"])
                        }
                    }
                } else {
                    Button("开启断网保护") {
                        if confirm("开启断网保护？", "会先预检（FlClash TUN、内核授权、出口白名单），加载规则后自检；任一失败会自动恢复，不会让你断网。建议先关闭浏览器和 Claude。") {
                            model.admin(["enable"])
                        }
                    }
                }
                Button(s?.realip == true ? "退出真实 IP 模式…" : "真实 IP 模式…") { showWizard = true }
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                if g?.lockdown == true {
                    Button("解除锁定") { model.releaseWithoutPassword() }.buttonStyle(.borderedProminent)
                }
                Button("刷新状态") { model.refreshStatus() }.keyboardShortcut("r")
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
        }
    }

    /// Only what needs the user's eyes; empty when everything is fine.
    func attentionItems(_ s: NGStatus?) -> [String] {
        guard let s = s else { return [] }
        var out: [String] = []
        if model.proxyOffIsolation {
            out.append("代理已断开：Claude 被隔离，浏览器等其他程序正在用真实 IP 上网。重新打开 FlClash 后，检查通过会自动解除。")
        } else if s.guardInfo?.lockdown == true {
            out += (s.guardInfo?.reasons ?? []).map { "锁定原因：" + $0 }
            out.append("问题解决后点右下角“解除锁定”；解除前会重新做全部检查。")
        } else {
            out += s.guardInfo?.last_findings ?? []
        }
        if s.wantedKillswitch == true && s.killswitchComplete != true { out.append("断网保护规则不完整。") }
        if let others = s.observations?.exempt_others, !others.isEmpty {
            out.append(others.joined(separator: "、") + " 与代理内核共用放行身份联网。")
        }
        if let moved = s.directCheck?.moved, !moved.isEmpty {
            out.append("Claude 主站解析到 Anthropic 网段以外：" + moved.joined(separator: "、"))
        }
        if let failed = s.claude?.last_cleanup?.failed, !failed.isEmpty {
            out.append("上次清理有 \(failed.count) 个 Claude 残留进程未能结束：" + summarizeNames(failed))
        }
        var seen = Set<String>()
        return out.filter { seen.insert($0).inserted }
    }
}

// MARK: Real IP wizard

struct RealIpWizard: View {
    @ObservedObject var model: Model
    @Binding var isPresented: Bool
    var body: some View {
        let s = model.status
        let o = s?.observations
        let inMode = s?.claudeBlock == true
        VStack(alignment: .leading, spacing: 14) {
            Text("真实 IP 模式").font(.title2.weight(.semibold))
            Text("需要暂时换到白名单以外的节点时使用：先隔离 Claude，再改代理；出口回到白名单后再退出。锁定期间请用“解除锁定”，不要用这里。")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            WizardStep(number: 1, title: "隔离 Claude", done: inMode) {
                HStack {
                    Text(inMode ? "Claude 已隔离：打开会被立即结束，Anthropic 网段连 TUN 也被拦截。" : "结束 Claude 桌面版、Claude Code 和它们启动的进程，之后打开也会被结束。")
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("隔离 Claude") { model.admin(["isolate"]) }.disabled(inMode)
                }
            }
            WizardStep(number: 2, title: "处理你的事情", done: false) {
                Text("现在可以在 FlClash 里切换节点或模式。完成后把 FlClash 恢复为白名单节点、全局模式、TUN 开启。")
                    .fixedSize(horizontal: false, vertical: true)
            }
            WizardStep(number: 3, title: "核对出口并退出", done: false) {
                Line(label: "普通出口", value: o?.egress ?? "未取得", ok: o?.egress_ok)
                Line(label: "claude.ai", value: o?.claude_egress ?? "未取得", ok: o?.claude_egress_ok)
                HStack {
                    Spacer()
                    Button("核对并退出真实 IP 模式") { model.admin(["unisolate"]) }
                        .disabled(!inMode || s?.guardInfo?.lockdown == true)
                }
            }
            HStack {
                if model.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("关闭") { isPresented = false }.keyboardShortcut(.cancelAction)
            }
        }
        .padding(22)
        .frame(width: 540)
    }
}

struct WizardStep<Content: View>: View {
    let number: Int
    let title: String
    let done: Bool
    @ViewBuilder var content: Content
    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle().fill(done ? Color.green : Color.accentColor).frame(width: 24, height: 24)
                if done {
                    Image(systemName: "checkmark").font(.caption.weight(.bold)).foregroundStyle(.white)
                } else {
                    Text(String(number)).font(.callout.weight(.semibold)).foregroundStyle(.white)
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(title).font(.headline)
                content
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(panelFill))
    }
}

// MARK: Records

struct RecordsView: View {
    @ObservedObject var model: Model
    @AppStorage("records.filter") private var filter = "important"
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Picker("", selection: $filter) {
                    Text("重要").tag("important")
                    Text("全部").tag("all")
                }
                .labelsHidden().pickerStyle(.segmented).frame(width: 160)
                Text("\(filtered.count) 条").font(.callout).foregroundStyle(.secondary)
                Spacer()
                Button("打开完整日志") { NSWorkspace.shared.open(URL(fileURLWithPath: ngRoot + "/netguard.log")) }
            }
            .padding(.horizontal, 16).padding(.vertical, 10)
            Divider()
            List {
                ForEach(Array(filtered.enumerated()), id: \.offset) { _, e in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Circle().fill(color(e.severity)).frame(width: 8, height: 8)
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(fmtTime(e.ts)).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
                                Text(eventNames[e.type ?? ""] ?? (e.type ?? "?"))
                                    .font(.caption.weight(.semibold))
                                    .padding(.horizontal, 6).padding(.vertical, 1)
                                    .background(Capsule().fill(color(e.severity).opacity(0.15)))
                            }
                            Text(e.summary ?? "").font(.callout).fixedSize(horizontal: false, vertical: true)
                            ForEach(Array((e.reasons ?? []).enumerated()), id: \.offset) { _, r in
                                VStack(alignment: .leading, spacing: 1) {
                                    Text("原因：\(r.text ?? "")（\(r.level ?? "")风险）").font(.caption.weight(.medium))
                                    if let why = r.why, !why.isEmpty, why != r.text {
                                        Text(why).font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                                .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .padding(.vertical, 4)
                    .textSelection(.enabled)
                }
            }
            .listStyle(.inset)
        }
    }

    var filtered: [NGEvent] {
        if filter == "all" { return model.events }
        let keep: Set<String> = ["trigger", "release", "release_refused", "rollback", "recover", "rules_restored",
                                 "config", "dns_relaxed", "exempt", "isolate", "unisolate", "cleanup", "anthropic_moved"]
        return model.events.filter { keep.contains($0.type ?? "") }
    }

    func color(_ s: String?) -> Color {
        switch s {
        case "高": return .red
        case "中": return .orange
        case "低": return .blue
        default: return .gray
        }
    }
}

// MARK: Maintenance

struct SettingsGroup<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline).padding(.leading, 4)
            VStack(alignment: .leading, spacing: 0) { content }
                .padding(.horizontal, 14).padding(.vertical, 4)
                .background(RoundedRectangle(cornerRadius: 10).fill(panelFill))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(panelStroke, lineWidth: 0.5))
        }
    }
}

/// Description on the left, the control on the right, like System Settings.
struct SettingRow<Control: View>: View {
    let title: String
    let detail: String
    var last = false
    @ViewBuilder var control: Control
    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center, spacing: 16) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.body.weight(.medium))
                    if !detail.isEmpty {
                        Text(detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 12)
                control
            }
            .padding(.vertical, 10)
            if !last { Divider() }
        }
    }
}

struct MaintenanceView: View {
    @ObservedObject var model: Model
    @State private var newIP = ""
    @State private var verifyOutput = ""

    var body: some View {
        let s = model.status
        let direct = s?.proxyDown == "direct"
        let policy = s?.claude?.policy ?? "full"
        let check = s?.directCheck
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                SettingsGroup(title: "保护设置") {
                    SettingRow(title: "代理断开时",
                               detail: direct ? "浏览器等程序用真实 IP 上网；Claude 立即隔离，Anthropic 网段和 Claude 的其他 \(plain(s?.directBlock)) 个地址只能经代理访问；代理恢复且检查通过后自动解除。" : "整台电脑只剩局域网可用，任何程序都不会用真实 IP 联网。") {
                        Picker("", selection: Binding(get: { direct ? "direct" : "block" }, set: { setProxyDown($0) })) {
                            Text("整机断网").tag("block")
                            Text("允许直连").tag("direct")
                        }
                        .labelsHidden().pickerStyle(.segmented).frame(width: 190)
                    }
                    if direct {
                        SettingRow(title: "Claude 主站网段",
                                   detail: check == nil ? "尚未核对（每 10 分钟经代理核对一次）" : ((check?.moved ?? []).isEmpty ? "claude.ai 等主站仍在 Anthropic 网段内，\(fmtTime(check?.at)) 核对" : "不在官方网段：" + (check?.moved ?? []).joined(separator: "、"))) {
                            let t = check == nil ? Tone.neutral : ((check?.moved ?? []).isEmpty ? Tone.ok : Tone.bad)
                            Image(systemName: t.symbol).foregroundStyle(t.color).font(.title3)
                        }
                    }
                    SettingRow(title: "Claude 退出后清理", detail: (cleanupNames[policy] ?? policy) + "。桌面版运行时一律放行；更新程序不会被打断。") {
                        Picker("", selection: Binding(get: { policy }, set: { p in if p != policy { model.admin(["cleanup", p]) } })) {
                            Text("全部").tag("full")
                            Text("仅桌面版").tag("desktop")
                            Text("关闭").tag("off")
                        }
                        .labelsHidden().pickerStyle(.segmented).frame(width: 220)
                    }
                    SettingRow(title: "自动防护", detail: "每 10 秒检查出口、规则、代理和 ClaudeGuard，异常时隔离 Claude。关闭不影响断网规则和现有锁定。", last: true) {
                        Toggle("", isOn: Binding(get: { s?.guardInfo?.enabled == true }, set: { on in
                            if on { model.admin(["guard-on"]) }
                            else if confirm("关闭自动防护？", "不影响断网保护规则和现有锁定，但不再自动锁定 Claude。") { model.admin(["guard-off"]) }
                        }))
                        .labelsHidden().toggleStyle(.switch)
                    }
                }

                SettingsGroup(title: "出口白名单") {
                    let wl = s?.whitelist ?? []
                    if wl.isEmpty {
                        Text("白名单为空：断网保护和解除锁定都会被拒绝。").foregroundStyle(.orange).padding(.vertical, 10)
                        Divider()
                    }
                    ForEach(wl, id: \.self) { ip in
                        VStack(spacing: 0) {
                            HStack {
                                Text(ip).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                                Spacer()
                                Button("删除") {
                                    if confirm("从白名单删除 \(ip)？", "删除后，出口为该 IP 时会被判定为不在白名单。断网保护开启时不能删除最后一个。") {
                                        model.admin(["whitelist", "remove", ip])
                                    }
                                }
                            }
                            .padding(.vertical, 8)
                            Divider()
                        }
                    }
                    HStack {
                        TextField("节点出口 IP 或网段", text: $newIP).textFieldStyle(.roundedBorder).frame(width: 220)
                        Button("添加") {
                            model.admin(["whitelist", "add", newIP.trimmingCharacters(in: .whitespaces)]) { ok, text in
                                if ok { newIP = "" }
                                showResult(ok, text)
                            }
                        }.disabled(newIP.trimmingCharacters(in: .whitespaces).isEmpty)
                        Spacer()
                        Button("从 ClaudeGuard 导入") { model.admin(["whitelist", "import-claudeguard"]) }
                    }
                    .padding(.vertical, 10)
                }

                SettingsGroup(title: "检查") {
                    SettingRow(title: "完整自检", detail: direct ? "核对出口、规则、DNS、拦截表是否真正生效、ClaudeGuard。" : "核对出口、规则、DNS、直连是否真正被拦、ClaudeGuard。") {
                        Button("运行") { model.admin(["verify"]) { _, text in verifyOutput = text } }
                    }
                    if !verifyOutput.isEmpty {
                        ScrollView {
                            Text(verifyOutput).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 220)
                        .padding(8)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .textBackgroundColor)))
                        .padding(.bottom, 10)
                        Divider()
                    }
                    SettingRow(title: "断线演练", detail: direct ? "只用于“整机断网”模式；直连模式请按验收清单手动验证。" : "自动退出 FlClash 约 45 秒，验证直连被拦并锁定 Claude，再自动恢复（约 1–4 分钟）。", last: true) {
                        Button("运行…") {
                            if confirm("运行断线演练？", "NetGuard 会自己退出 FlClash，断开约 45 秒，验证直连被拦截、锁定 Claude，然后重新打开 FlClash。期间整机只能访问局域网；3 分钟内网络未恢复会自动紧急恢复。请先保存工作、关闭浏览器和 Claude。") {
                                model.admin(["drill"]) { ok, text in verifyOutput = text; showResult(ok, text) }
                            }
                        }
                        .disabled(direct)
                    }
                }

                SettingsGroup(title: "维护工具") {
                    SettingRow(title: "修复 ClaudeGuard", detail: "Claude 更新后显示“记录过期”时使用：应用兼容补丁，再运行 claudeguard doctor。") {
                        Button("修复") { model.repairClaudeGuard() }
                    }
                    SettingRow(title: "自动更新", detail: model.updateText + "。装好或回滚都会通知你。") {
                        HStack(spacing: 8) {
                            Button("立即检查…") { model.update() }
                            Toggle("", isOn: Binding(get: { s?.update?.enabled != false }, set: { on in
                                if on { model.admin(["update", "enable"]) }
                                else if confirm("关闭自动更新？", "关闭后 NetGuard 和 ClaudeGuard 都不再自动更新；上游变化可能让旧版本无法使用。") { model.admin(["update", "disable"]) }
                            })).labelsHidden().toggleStyle(.switch)
                        }
                    }
                    SettingRow(title: "安装来源", detail: "\(s?.source?.repo ?? "未记录") @ \(s?.source?.commit ?? "?")，\(s?.source?.installed_at ?? "?") 安装") {
                        Button("打开目录") { NSWorkspace.shared.open(URL(fileURLWithPath: ngRoot)) }
                    }
                    SettingRow(title: "紧急恢复", detail: "移除 NetGuard 的全部规则并关闭断网保护。没有网络时也可以双击“应用程序”里的“NetGuard 紧急恢复”。") {
                        Button("紧急恢复…") {
                            if confirm("执行紧急恢复？", "会移除 NetGuard 的全部 pf 规则并关闭断网保护。只在断网且无法恢复时使用。") {
                                NSWorkspace.shared.open(URL(fileURLWithPath: recoverCommand))
                            }
                        }
                    }
                    SettingRow(title: "卸载 NetGuard", detail: "移除规则、后台、菜单栏程序和急救入口，配置与记录保留一份副本。", last: true) {
                        Button("卸载…") { model.uninstall() }
                    }
                }
            }
            .padding(16)
        }
    }

    func setProxyDown(_ value: String) {
        let current = model.status?.proxyDown == "direct" ? "direct" : "block"
        guard value != current else { return }
        if value == "direct" {
            if confirm("代理断开时允许直连？", "代理断开后，浏览器等程序会用真实 IP 上网；Claude 会被立即隔离，Anthropic 网段和 Claude 的其他已知地址仍只能经代理访问。建议关代理前先退出 Claude、关闭 claude.ai 网页。切换会重新开启断网保护并自检（需要代理此刻正常）。") {
                model.admin(["proxy-down", "direct"])
            }
        } else if confirm("代理断开时整机断网？", "代理一断，整台电脑只剩局域网可用。切换会重新开启断网保护并自检（需要代理此刻正常）。") {
            model.admin(["proxy-down", "block"])
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
        menu.addItem(withTitle: "刷新状态", action: #selector(refreshNow), keyEquivalent: "r").target = self
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
    @objc func releaseLockdown() { model.releaseWithoutPassword() }
    @objc func refreshNow() { model.refreshStatus() }
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

