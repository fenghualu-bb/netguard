# NetGuard

**给 Claude 用的断网保护（kill switch）与出口守护。** 代理一断，整机不会退回用真实 IP 直连；出口一旦不在你的白名单里，几秒内就隔离 Claude 桌面版和 Claude Code。支持 **Windows 11**（WFP）和 **macOS 13+**（pf）。

[![macOS NetGuard](https://github.com/fenghualu-bb/netguard/actions/workflows/macos.yml/badge.svg)](https://github.com/fenghualu-bb/netguard/actions/workflows/macos.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> 非官方项目，与 Anthropic、FlClash、ClaudeGuard 均无关联。请遵守你所用服务的条款和当地法律。

## 它做什么

| 能力 | 说明 |
|---|---|
| 断网保护 | 只放行进入代理 TUN 的流量、代理内核自身、局域网和回环；代理或 TUN 一掉，只剩局域网可用，不会用真实 IP 直连。IPv4 和 IPv6 都覆盖。 |
| 出口守护 | 持续核对普通出口和 claude.ai 出口是否在白名单。出口不在白名单时第一次发现就锁定（macOS 两次检查之间每 3 秒快速复查）。 |
| 隔离 Claude | 锁定或进入“真实 IP 模式”时，立即结束 Claude 桌面版和 Claude Code，重新打开也会被结束；直到检查全部通过、你本人解除。 |
| 防绕过 | 发往 Anthropic 官方网段的非 TUN 流量一律拒绝；macOS 版还会发现其他程序能越过断网保护的 pf 放行规则。 |
| 可恢复 | 开启失败自动回滚；有不需要网络的紧急恢复入口。从不修改系统主防火墙配置（macOS 不改 `/etc/pf.conf`）。 |

依赖另行安装的 [FlClash](https://github.com/chen08209/FlClash)（TUN 模式）和 [ClaudeGuard](https://github.com/ivblz/ClaudeGuard)。NetGuard 不是代理，也不提供节点。

## 选择平台

| 平台 | 入口 | 实现 |
|---|---|---|
| **macOS 13+**（Apple Silicon / Intel） | [macos/README.md](macos/README.md) | pf 独立锚点 + LaunchDaemon + 菜单栏工作台；CI 在一次性 macOS 虚拟机上做真实内核测试 |
| **Windows 11** | 本页下方“Windows 版” | WFP 双栈规则 + SYSTEM 看门狗 + Tk 工作台 |

让 Codex 或 Claude Code 帮你安装前，先让它读对应的 `AGENTS.md`（[macOS](macos/AGENTS.md)）。

## 局限（如实说明）

- 绿色状态只表示“当前检查通过”，不能证明不会泄露；停代理、睡眠唤醒、切换网络要按 [macOS 验收清单](macos/ACCEPTANCE.md) 在真机上验证。
- 代理内核自己的 DIRECT 流量仍走真实 IP（与 FlClash 规则有关），所以要求全局模式。
- 未列入的 Claude 子域名靠 ClaudeGuard 的 hosts 拦截兜底。

更多见各平台 README 的“已知限制”。

## 反馈与安全

提交 issue 前请**删掉你的出口 IP、真实 IP、用户名和路径**——issue 是公开的。安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 许可

NetGuard 自有代码使用 [MIT 许可](LICENSE)。`patches/claudeguard/` 下的 ClaudeGuard 补丁保留上游 MIT 许可，第三方说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

---

## Windows 版

Windows 11 上的本地工作台与 WFP 断网保护，当前源码版本 **1.3.5**。这是一套已有本机部署的源码快照，不是一键安装包。

### 组成

- `workbench.pyw`：普通权限 Tk 工作台，显示出口、守护、规则完整性、严格路由运行时证据与保护记录；管理操作通过本人确认 UAC 执行。
- `admin/netguard.ps1`：管理员/SYSTEM 后台，常驻检查、隔离、人工解除及状态输出。
- `admin/netguard_wfp.cs`：WFP 双栈规则和事务操作。基础断网保护允许代理、TUN 与本地通信，阻断其他直连和绕过 TUN 的 DNS。
- `install.ps1`：安装受保护脚本与 SYSTEM 看门狗任务，保留已有配置/状态并备份；初次安装不会自动开启保护。
- `patches/claudeguard/runtime.py`：ClaudeGuard 本地守护补丁快照，记录分级保护动作；保留上游 MIT 许可，应用前必须核对版本。
- `tests/`：离线回归和布局检查，不对真实 WFP 或 Claude 进程执行管理操作。

### 前提与启动

已有部署使用以下位置：

```text
%LOCALAPPDATA%\Programs\ClaudeGuard\
%LOCALAPPDATA%\Programs\FlClash\
%LOCALAPPDATA%\Programs\NetGuard\
%ProgramData%\NetGuard\
```

工作台使用 ClaudeGuard 的 Python 环境（需要 `psutil`、Tk）；此快照在 Python 3.13.12 / psutil 7.2.2 上验证。不要在已有电脑上仅为查看源码运行管理员安装器。正式安装与更新流程见 [运维说明](docs/OPERATIONS.md)。

启动已有部署：

```powershell
& "$env:LOCALAPPDATA\Programs\ClaudeGuard\venv\Scripts\pythonw.exe" "$env:LOCALAPPDATA\Programs\NetGuard\workbench.pyw"
```

### 验证

以下命令在仓库根目录运行，要求 Windows PowerShell 5.1、已有 ClaudeGuard Python 环境及其源模块：

```powershell
$python = "$env:LOCALAPPDATA\Programs\ClaudeGuard\venv\Scripts\python.exe"
& $python -X utf8 -m unittest discover -s tests -p 'test_*.py'
if ($LASTEXITCODE -ne 0) { throw 'Python tests failed' }
foreach ($test in @('test_admin.ps1', 'test_isolation_sync.ps1', 'test_release_requirements.ps1', 'test_store_lifecycle.ps1', 'test_state_mutex.ps1')) {
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path tests $test)
    if ($LASTEXITCODE -ne 0) { throw "Failed: $test" }
}
& $python -X utf8 tests/check_layout.py 96
if ($LASTEXITCODE -ne 0) { throw '96ppi layout check failed' }
& $python -X utf8 tests/check_layout.py 192
if ($LASTEXITCODE -ne 0) { throw '192ppi layout check failed' }
```

ClaudeGuard 补丁测试加载本仓库的 runtime 快照，并使用已安装 ClaudeGuard 的其余依赖；不会自动覆盖已安装文件。测试数据中的 `203.0.113.10` 是文档示例地址，与实际白名单无关。布局检查会短暂创建离线 Tk 测试窗口。

源码测试不能代替实际出口、规则新鲜度、直连/DNS/LAN 和应用使用验证。界面绿色只表示“当前检查通过（未做断线测试）”。真实停代理、启动阶段、WSL/VM 等边界不能据此宣称没有泄露。

### 同步范围

本仓库只收录源码、测试和脱敏运维资料。没有运行配置、节点/订阅、代理地址、凭证、状态/日志、helper manifest、备份、截图或个人记忆。运行中的白名单由本机配置决定；本次 Git 同步不改变已部署程序或网络。

历史修复见 [变更记录](docs/CHANGELOG.md)，来源哈希见 [源码快照](docs/SOURCE_SNAPSHOT.md)，第三方许可见 [说明](THIRD_PARTY_NOTICES.md)。
