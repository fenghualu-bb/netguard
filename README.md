# NetGuard

Windows 11 上用于 Claude 网络环境的本地工作台与 WFP 断网保护。当前源码版本 **1.3.5**。

这是一套已有本机部署的源码备份，依赖另行安装的 [ClaudeGuard](https://github.com/ivblz/ClaudeGuard) 和 [FlClash](https://github.com/chen08209/FlClash)，不是独立的一键安装包。

## 组成

- `workbench.pyw`：普通权限 Tk 工作台，显示出口、守护、规则完整性、严格路由运行时证据与保护记录；管理操作通过本人确认 UAC 执行。
- `admin/netguard.ps1`：管理员/SYSTEM 后台，常驻检查、隔离、人工解除及状态输出。
- `admin/netguard_wfp.cs`：WFP 双栈规则和事务操作。基础断网保护允许代理、TUN 与本地通信，阻断其他直连和绕过 TUN 的 DNS。
- `install.ps1`：安装受保护脚本与 SYSTEM 看门狗任务，保留已有配置/状态并备份；初次安装不会自动开启保护。
- `patches/claudeguard/runtime.py`：ClaudeGuard 本地守护补丁快照，记录分级保护动作；保留上游 MIT 许可，应用前必须核对版本。
- `tests/`：离线回归和布局检查，不对真实 WFP 或 Claude 进程执行管理操作。

## 前提与启动

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

## 验证

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

## 同步范围

本仓库只收录源码、测试和脱敏运维资料。没有运行配置、节点/订阅、代理地址、凭证、状态/日志、helper manifest、备份、截图或个人记忆。运行中的白名单由本机配置决定；本次 Git 同步不改变已部署程序或网络。

历史修复见 [变更记录](docs/CHANGELOG.md)，来源哈希见 [源码快照](docs/SOURCE_SNAPSHOT.md)，第三方许可见 [说明](THIRD_PARTY_NOTICES.md)。本仓库未对 NetGuard 自有代码另行授予开源许可；第三方部分按各自许可保留权利。
