# 源码导出验证

## 1.3.5 — 2026-11-11

在本仓库副本上运行：Python `unittest` 65 项通过（57 项工作台 + 8 项 ClaudeGuard runtime 快照）；Windows PowerShell 5.1 按文件统计共 79 条 PASS（test_admin 40、test_isolation_sync 13、test_release_requirements 12、test_state_mutex 5、test_store_lifecycle 9），无 FAIL；全部 PowerShell 文件的语法和 UTF-8 BOM 检查通过；96 ppi 和 192 ppi 下 53/53 个按钮均位于窗口或可滚动区域内。本次新增宽限期相关的 9 项 PowerShell 回归测试和 3 项工作台回归测试。应用与管理员源文件和本机安装源逐字节一致（见 SOURCE_SNAPSHOT）。用户于 2026-11-11 08:11 本人确认 UAC，在本机安装了 1.3.5 后台。安装后核对结果：文件逐字节一致，`grace_until` 字段存在，规则 14/14，无锁定，检查间隔 10 秒。宽限期在真实开机时的效果，要等下次开机后才能确认。

## 1.3.4 源码导出 — 2026-11-10

日期：2026-11-10。范围是此仓库的源码快照与测试；本次未修改或复验当前电脑的运行网络环境。

- Python 3.13.12 / psutil 7.2.2，`unittest discover`：62项通过（54工作台、8仓库ClaudeGuard runtime快照）。
- Windows PowerShell 5.1：66项通过（31基础、12清单同步、11身份/人工解除、8Store生命周期、4状态Mutex）。
- C#只编译、不打开WFP引擎；7份PowerShell源码语法及UTF-8 BOM检查通过。
- 96/192ppi：各8个窗口/页面、53个按钮均在窗口或可滚动区域内。
- 4份应用/管理员源文件、ClaudeGuard runtime及其许可与本机源字节一致；导出哈希见SOURCE_SNAPSHOT。
- 测试fixture出口已用文档保留地址替换；runtime测试改为加载仓库快照，依赖其余已安装ClaudeGuard模块。

保护动作、进程结束和网络助手失败的测试输出来自替身，不代表测试对真实程序执行了这些动作。ClaudeGuard日志初始化存在既有ResourceWarning（测试临时日志句柄未全部清理）；断言通过，本次没有修改生产代码消除该告警。

上传清单采用显式源码白名单；运行配置/日志/状态/helper清单/备份/截图/个人记忆均排除。只做模式检查和人工复审不等于对所有未来提交保证无秘密；后续仍须逐次检查新增文件。历史真实网络验收记录不随此源码仓库上传，不能把此处的离线结果当作当前运行状态或全面无泄露证明。
