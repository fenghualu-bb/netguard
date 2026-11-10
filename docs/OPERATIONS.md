# 运维说明（脱敏版）

## 保护目标和权限

优先保护 Claude 相关流量不经真实出口发出，然后恢复白名单出口可用性。白名单、代理配置和安装路径来自本机数据，本仓库不提供可直接套用的个人配置。

只读诊断先于修改。会中断代理或替换网络助手的操作，必须先说明真实 IP 风险，等待用户明确确认已关闭其他浏览器、Claude 等联网程序；管理员 UAC 由本人确认。任何时候都不能静默关闭保护、扩大白名单或改成 DIRECT。

## 组件和文件

| 组件 | 本机来源 | 责任 |
|---|---|---|
| FlClash | `%LOCALAPPDATA%\Programs\FlClash` | 代理、内核、TUN、全局模式 |
| ClaudeGuard | `%LOCALAPPDATA%\Programs\ClaudeGuard` | 白名单检查及 SYSTEM 网络助手 |
| NetGuard 源码 | `%LOCALAPPDATA%\Programs\NetGuard` | 普通权限工作台及待安装脚本 |
| NetGuard 运行副本 | `%ProgramData%\NetGuard` | 管理员保护的后台、配置和状态 |
| ClaudeGuard helper | `%ProgramData%\ClaudeGuardNetwork\<installation-id>` | 受保护的程序清单和执行助手 |

工作台读取正在运行的 FlClash 进程环境来定位配置。若文件看似空白、旧版本或读取失败，应核对读取账户和文件元数据，不要据此重载代理。禁止打印节点、订阅、代理地址或整个配置文件。

## 只读诊断

- 比较 Store 当前用户注册版本、后台的 `Installed` 包、ClaudeGuard 的 Desktop/CLI 路径与 helper manifest；逐项核实文件存在性。
- 查询 ClaudeGuard：出口为 allowed、daemon 正在运行、helper ready 且状态新鲜。仅 allowed 不能证明 helper 已保护当前程序。
- 分别核对普通域名与 Claude 域名的 `/cdn-cgi/trace` 出口是否属于本机白名单；主站 HTTP 403 不等于 Claude 不可用。
- 检查 FlClash UI/内核/Helper 进程、TUN Up、global 模式。
- 检查 `%ProgramData%\NetGuard\status.json` 的 schema、新鲜度、error、规则计数、独立基础/隔离完整性及 guard 当前异常。
- 严格路由以新鲜 WFP 运行时证据为准：同一 owner 下 DNS block 和内核 protect 规则成组出现。owner 名称不写死；配置写 true 不等于运行时证据。
- 普通用户无法直接枚举 WFP 时，使用 SYSTEM 写入的状态，不自行提权绕过约定。

基础规则数通常为 14（两项代理程序时），隔离规则为每个受保护 exe 的 IPv4/IPv6 各一条。清单变化后数量可能不同；保留的额外旧 DENY 可以存在。单看总数完整不能证明新版本已纳入清单。

## 常见处理顺序

### Store 暂存更新

`Staged` 仅说明包已下载；只有存在 `PackageUserInformation.InstallState=Installed` 注册的包才参与当前版本选择。不要把暂存新版本当成路径过期，也不要把 ClaudeGuard 指向尚未注册的暂存包。无法核实 Installed 身份时，人工解除应失败。

### 真正安装完成，旧路径消失

保持锁定和基础保护；按前述风险确认流程执行 ClaudeGuard 的既有修复入口（工作台“维护 → 修复 ClaudeGuard”或其 monitor/fix.cmd），备份配置、更新准确路径、重装网络助手。核对 Desktop/CLI、新 manifest、全部 exe、助手新鲜且 ready 后，才人工解除锁定。助手替换期间不能把返回码或旧状态当作已恢复证明。

### 隔离清单扩展

1.3.3 起，锁定时可用事务只补缺失 DENY，保留原规则及锁定，不自动解除。基础保护不完整时拒绝自动修复。人工 release 仍须检查双出口、守护/helper、当前程序身份及规则。

### 状态锁权限

SYSTEM watch 与管理员操作使用同名 `Global\NetGuardState`。仅 SYSTEM 和 BuiltinAdministrators 获授权。更新要停止旧 watch，让旧对象最后一个 handle 释放后重建；传入新 MutexSecurity 不会修改已有对象。不要换锁名、开放 Everyone 或直接写状态绕过错误。

## 更新与验收

更新前备份源码/配置为带日期的 `.bak-*`，在本人 UAC 下运行工作台的“更新 / 重新安装管理脚本”；这只更新 NetGuard 任务，保留持久 WFP 规则和配置。初次安装不自动开启保护。后台更新后比较源码与受保护副本，再验证新鲜状态。

完成条件：基础保护完整、无意外隔离/锁定、无当前异常、助手就绪、双出口在白名单、全局/TUN/严格路由证据正常、健康检查 OK。另做非破坏性测试：绑定实际物理 LAN 地址的直连 HTTPS 必须失败，LAN 路由器 HTTP 应可达，绑定 LAN 的路由器及公网 DNS 查询应超时。不可套用他人的网卡 IP。

界面应显示“当前检查通过（未做断线测试）”。真实停止代理、WSL/VM、启动阶段和 Claude 登录/对话功能另行验收，不能从离线回归推断。退出锁定后才重新打开 Claude。
