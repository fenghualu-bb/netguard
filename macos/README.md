# NetGuard for macOS

Windows 版 NetGuard 的 macOS 适配版：给 Claude 用的**断网保护（kill switch）+ 出口守护 + 锁定**，配菜单栏图标和工作台窗口。

用 macOS 自带的 **pf 防火墙**实现，**不需要** Apple 开发者账号、签名、系统扩展、VPN 描述文件，也不需要关闭 SIP。

> **断网急救（不需要网络，也不需要 Codex）**
> 1. 双击“应用程序”文件夹里的 **NetGuard 紧急恢复**，输入登录密码；或
> 2. 打开“终端”，运行 `sudo /Library/NetGuard/bin/netguard-recover`；或
> 3. NetGuard 文件都没了也能用：`sudo pfctl -a com.apple/zz.NetGuard -F rules`
>
> 这三种方式都只移除 NetGuard 自己的规则。重启电脑**不会**解决“断网保护拦住了网络”的问题，因为后台开机后会重新加载规则。断网时请用上面的方法，**不要恢复出厂**。

---

## 它做什么

| 功能 | 说明 |
|---|---|
| 断网保护 | 拦截所有出站流量，只放行：进入 FlClash TUN 的流量、FlClash 内核自己的流量、局域网/链路本地/组播、回环。代理或 TUN 一掉，整机只能访问局域网，**不会退回用真实 IP 直连**。 |
| Anthropic 网段硬拦截 | 发往 Anthropic 官方网段（160.79.104.0/23、153.61.224.0/22、2607:6bc0::/48）的流量，**只要不是从 TUN 出去的一律拒绝**，连 FlClash 内核也不例外。所以即使 FlClash 规则把 Claude 误设为 DIRECT，也连不上。Windows 版没有这一层。 |
| 自动防护 | 每 10 秒检查一次：普通出口和 claude.ai 出口是否在白名单、断网规则是否完整、有没有其他程序的 pf 放行规则能越过断网保护（排在 NetGuard 之前的 quick 放行，或排在它之后的放行）、FlClash 内核是否以 root 运行、TUN 是否在线且公网流量真的经过它、FlClash 是否为**全局模式**、ClaudeGuard 是否在运行且保护开启、它的 root 网络助手是否在运行、`claude` 命令和桌面版是否仍挂在 ClaudeGuard 上。连续 2 次异常就**锁定**；但**出口不在白名单**（普通出口或 claude.ai 出口）第一次发现就锁定，不等第二次。两次完整检查之间，每 3 秒还会快速读一次普通出口，发现变了立即做完整检查，所以换节点后约 3～5 秒内结束 Claude（原来最长约 20 秒）。 |
| 锁定 / 隔离 | 立即结束 Claude 桌面版和 Claude Code，之后由独立线程**每 0.25 秒**检查一次并直接强制结束（与 Windows Stop-Process -Force 相同），重新打开也会被结束；同时在 TUN 内也拒绝 Claude：Anthropic 官方网段连 TUN 也拒绝；FlClash 用 fake-ip 时 Claude 域名解析到的是 198.18.x.x 代理地址，看不到真实网段，所以后台还会向 FlClash 查询 Claude 常用域名的代理地址，放进 pf 地址表 `ng_claude` 一并拒绝（每 60 秒刷新）。直到你在工作台点“解除锁定”。解除前会重新做全部检查，有一项不通过就拒绝解除。 |
| 宽限期 | 开机、登录、睡眠唤醒后 180 秒内，中危异常（内核/TUN/ClaudeGuard 还没起来）只记录一条，不锁定；高危异常照常锁定。与 Windows 1.3.5 相同。 |
| 关机锁定自动解除 | 关机或重启时，macOS 会先退出 FlClash 和 ClaudeGuard，再停止 NetGuard 后台，后台因此会在关机过程中触发一次锁定。如果这次锁定**只由中危异常引起**，并且发生在本次开机前 10 分钟内，开机后后台会反复做与“解除锁定”完全相同的检查（两个出口都在白名单、断网规则完整、内核和 TUN 正常、ClaudeGuard 在运行），全部通过才自动解除，并留下记录。高危锁定（出口不在白名单、规则不完整）仍然必须手动解除。 |
| 真实 IP 模式 | 工作台里有三步向导（与 Windows 相同）：隔离 Claude → 处理你的事情 → 核对出口回到白名单后退出。 |
| 局域网 DNS | 默认 `auto`：开启断网保护时先**拦截**发往路由器的 DNS（与 Windows 相同）；如果这台 Mac 的系统 DNS 就是路由器、拦了就无法解析，则自动放行并记录。之后换了 Wi‑Fi、DNS 变得不可用时，后台也会自动放行，**绝不让你失去 DNS**。 |
| 放行身份监测 | 每分钟检查是否有其他程序以“root + 你的用户组”身份联网（与 FlClash 内核共用放行身份），发现就记录并通知。Windows 版没有这项检查。 |
| 界面 | 菜单栏盾牌图标（绿=当前检查通过，黄=保护未开，橙=有异常或真实 IP 模式，红=锁定/规则不完整，灰=后台没运行）。工作台与 Windows 布局一致：概览（当前出口、出口 IP、自动防护、ClaudeGuard、FlClash、断网保护、最近操作）、保护记录（可筛选）、维护（白名单、自动防护、完整自检、修复 ClaudeGuard、更新、卸载、日志、急救）。系统通知会提示锁定、代理未就绪、DNS 放行和放行身份被占用。 |

锁定策略按你的要求与 Windows 版一致：中危异常（内核、TUN、ClaudeGuard 未就绪）在宽限期外连续出现 2 次也会锁定。出口不在白名单比 Windows 更严：第一次发现就锁定。

## 为什么这次不会像上次那样断网

上次 Mac 上的那次尝试具体装了什么，现在已经无法查清（已恢复出厂）。可以确定的是，“连得上 Wi‑Fi 但什么都打不开、重启也没用”通常是这几种情况之一。针对每一种的防护如下：

| 可能的原因 | 本项目的防护 |
|---|---|
| 断网规则把代理内核自己也拦了，形成死循环 | 开启前检查 FlClash 内核**确实以 root 运行**（TUN 已授权），才生成放行它的规则；内核没授权时拒绝开启。CI 在真实 macOS 上验证过：这条放行规则只放行 root + 用户组，不放行普通程序和 root 后台程序。 |
| 改了 `/etc/pf.conf` 或重载了主规则集，开机后反复生效 | **从不**写 `/etc/pf.conf`，**从不**重载主规则集，**从不**执行 `pfctl -d` / `-F all`。规则只放在独立锚点 `com.apple/zz.NetGuard` 里。CI 会对比安装前后的 pf.conf、hosts 和主规则集。 |
| DNS 被拦（系统 DNS 是路由器，没走 TUN） | `block_lan_dns=auto`：只有确认拦截后 DNS 仍能解析（不经缓存直接查询）才拦截，否则自动放行；运行中 DNS 失效也会自动放行并通知。 |
| 装了系统扩展、网络过滤器或 VPN 描述文件，卸不干净 | 一样都不装。只有一个 LaunchDaemon 和一个菜单栏程序，卸载脚本会全部删除。 |
| 开启后网络坏了，但没人能撤回 | `enable` 加载规则后马上自检：DNS 能解析、代理出口可用且在白名单、绑定物理网卡直连**必须失败**。任一项不通过就**立即回滚**。如果 enable 进程中途被杀，后台会在下一次检查（10 秒内）自动回滚。 |
| 没网时 Codex 也帮不上忙 | 紧急恢复是纯 shell 脚本，不需要网络，也不需要 Python；“应用程序”里有一个可以双击的入口。 |

## 前提

- macOS 13 及以上，Apple Silicon 或 Intel（目标机器：M2，macOS 15.x）
- Xcode Command Line Tools：`xcode-select --install`。它提供 Python 3.9+ 和编译菜单栏程序用的 swiftc，不需要完整的 Xcode
- **FlClash**，开启 **TUN** 并已授权内核（FlClash 会弹出密码框，把内核改成 root 所有的 setuid 程序），TUN 地址保持默认的 198.18.0.1/16，建议用全局模式，并设为**登录时启动**
- **ClaudeGuard**：上游 macOS 版（[ivblz/ClaudeGuard](https://github.com/ivblz/ClaudeGuard)，MIT 许可），已加入白名单 IP

## 安装（每条 `sudo` 命令都由你本人在“终端”里运行）

> 下面的第 5 步会加载断网规则。动手前请**关闭浏览器、Claude 等联网程序**。加载过程中若有问题会自动回滚，但这一步前后有几秒钟属于风险窗口。

**1. FlClash**

1. 安装 FlClash（[chen08209/FlClash](https://github.com/chen08209/FlClash) Releases 里的 macos-arm64.dmg），导入订阅。
2. 打开 **TUN**，按提示输入密码授权内核；模式选全局（与 Windows 一致）；打开“开机自启”。
3. 在终端确认出口是节点 IP，并确认内核以 root 运行：
   ```bash
   curl -s https://www.cloudflare.com/cdn-cgi/trace | grep ^ip=
   ps -axo uid,rgid,comm | grep FlClashCore      # 第一列必须是 0
   ifconfig | grep 198.18.                        # 必须有一行 inet 198.18.0.1
   ```

**2. ClaudeGuard（上游 macOS 版）**

```bash
git clone https://github.com/ivblz/ClaudeGuard.git ~/ClaudeGuard
cd ~/ClaudeGuard && git checkout 61b61e1   # 2026-11-08 的版本；升级前先看它的变更
./install.sh
```
安装时它会问是否把当前 IP 加入白名单：**只有在代理已连上时**才回答“是”。

> ClaudeGuard 61b61e1 找不到新版官方原生 Claude Code（每个版本是 `~/.local/share/claude/versions/<版本号>` 这样的单个文件），`claudeguard doctor` 会显示 `Hands off to: NOT FOUND`，`claude` 命令无法启动。NetGuard 的 `install.sh` 会自动打一个**只加一行搜索路径**的兼容补丁：打补丁前后都校验文件哈希，文件不是这个版本就拒绝修改，并保留备份；也可以用 `--revert` 还原。重装 ClaudeGuard 后，在工作台维护页点“修复 ClaudeGuard”即可重新打上。

**3. 获取本仓库**（私有仓库，需要先登录 GitHub）

```bash
gh auth login        # 没装 gh 就用浏览器下载 zip
gh repo clone fenghualu-bb/netguard ~/netguard
cd ~/netguard
```

**4. 安装 NetGuard**（不会开启断网保护，也不会改网络）

```bash
sudo bash macos/install.sh
```

**5. 检查白名单，然后开启断网保护**

```bash
sudo /Library/NetGuard/bin/netguard whitelist list
sudo /Library/NetGuard/bin/netguard whitelist import-claudeguard   # 为空时从 ClaudeGuard 导入
sudo /Library/NetGuard/bin/netguard enable
```

**6. 完整自检**

```bash
sudo /Library/NetGuard/bin/netguard verify
```
每一项都应该是 ✅。也可以点菜单栏的盾牌图标，选“打开工作台”。

## 日常命令

```bash
/Library/NetGuard/bin/netguard status            # 状态（不需要 sudo）
/Library/NetGuard/bin/netguard events -n 50      # 保护记录
sudo /Library/NetGuard/bin/netguard release      # 解除锁定（先完整检查）
sudo /Library/NetGuard/bin/netguard disable      # 关闭断网保护（同时解除锁定）
sudo /Library/NetGuard/bin/netguard isolate      # 真实 IP 模式：隔离 Claude
sudo /Library/NetGuard/bin/netguard unisolate    # 退出（出口需回到白名单）
sudo /Library/NetGuard/bin/netguard guard-off    # 关闭自动防护（规则不变）
```
工作台里的按钮调用的是同样的命令，执行前会弹出 macOS 的管理员密码框，相当于 Windows 的 UAC。

## 自动断线演练

```bash
sudo /Library/NetGuard/bin/netguard drill
```
NetGuard 会自己退出 FlClash，确认 TUN 消失后保持断开 45 秒，每 2 秒采样一次：公网请求必须全部失败；如果有请求成功，会记下出口 IP，出现非白名单出口就判为泄露。同时检查局域网网关是否可达、是否在 TUN 消失后约 20 秒触发锁定。之后它会重新打开 FlClash，等网络恢复；3 分钟内没恢复，就自动执行紧急恢复，不会让你断网。整个过程不需要你配合计时，采样记录保存在 `/Library/NetGuard/drill-*.jsonl`。演练结束后 Claude 会处于锁定，这是预期结果，解除即可。Windows 版没有这个功能。

## 卸载

```bash
sudo bash /Library/NetGuard/uninstall.sh          # 会保留一份配置和保护记录
sudo bash /Library/NetGuard/uninstall.sh --purge  # 全部删除
```

## 与 Windows 版逐项对比（目标：只多不少）

| 能力 | Windows 1.3.5 | macOS | 结论 |
|---|---|---|---|
| 断网保护（只放行 TUN / 代理内核 / 局域网 / 回环，IPv4+IPv6） | WFP 持久规则 | pf 独立锚点，开机由纯 shell 在 Python 之前加载 | 等价（CI 真机逐项验证） |
| 发往 Anthropic 网段的 DIRECT 流量 | 不拦 | 非 TUN 一律拒绝；隔离时连 TUN 也拒绝（fake-ip 下按 Claude 域名的代理地址拒绝） | **Mac 更强** |
| 局域网 DNS | 拦截 | 能拦就拦（auto），拦了会断网时才放行 | 等价；只在“拦了就上不了网”的网络上放行 |
| 代理模式 | 只显示 | 显示，非全局模式记为异常并锁定 | **Mac 更强** |
| 流量是否真的经过 TUN | 严格路由运行时证据（WFP） | 路由核对：公网路由必须指向 TUN | 等价 |
| ClaudeGuard 守护 / 保护开关 / 网络助手 | 有 | 有 | 等价 |
| Claude 路径与钩子（claude_path，高危） | Store 版本与清单核对 | `claude` 命令钩子 + ClaudeGuard 记录的路径核对（等 ClaudeGuard 60 秒自愈后才计数） | 等价 |
| 隔离 Claude | WFP 按程序断网 + 结束进程 | 独立线程每 0.25 秒强制结束进程 + 隔离期间 Anthropic 网段及 Claude 域名的 fake-ip 地址连 TUN 也拒绝 + ClaudeGuard 的 hosts 拦截与启动前检查 | 等价（机制不同，见限制） |
| 识别代理内核 | 按程序路径 | 按 root + 用户组，**另加**每分钟监测有无其他程序共用该身份 | 等价（多一层监测） |
| 关机过程中产生的误锁 | 需手动解除 | 开机后检查全部通过自动解除 | **Mac 更强** |
| 开启失败 / 中途被杀 | 自动回滚 | 自动回滚 + 后台 10 秒内回滚中途被杀的操作 | **Mac 更强** |
| 断网急救 | 无专门入口 | 双击“NetGuard 紧急恢复”（无需网络和 Python） | **Mac 更强** |
| 工作台 | 概览 / 记录 / 维护、真实 IP 向导、修复 ClaudeGuard、更新/重装 | 同上，另有菜单栏图标与系统通知 | 等价或更多 |

## 已知限制（如实说明）

- **只读的状态检查不能证明不会泄露。** 绿色只表示“当前检查通过（未做断线测试）”。停代理、睡眠唤醒、切换网络要按 [ACCEPTANCE.md](ACCEPTANCE.md) 在真机上验收。
- **隔离机制不同**：macOS 的 pf 不能按程序拦截，所以隔离靠“独立线程每 0.25 秒强制结束进程”。隔离期间，经 TUN 发往 Claude 常用域名（claude.ai、claude.com、anthropic.com 的主要子域，列表见 `netguard/claude.py`）的连接也会被拒绝，浏览器打开 claude.ai 同样不通。列表以外的子域名不在其中，要靠 ClaudeGuard 的 hosts 拦截和启动前检查兜底，所以 ClaudeGuard 默认是必需的。FlClash 内核未运行时无法查询，地址表保持上一次的内容。
- **开机最早的几秒**：Windows 的规则由系统在开机最早阶段加载；Mac 由 LaunchDaemon 加载，最早一两秒内系统后台程序可能先联网。要做到和 Windows 一样早，只能修改 `/etc/pf.conf`，而这正是上次让 Mac 无法恢复的高风险做法，所以刻意不做。这时你还没登录，Claude 不可能在运行。
- **局域网 DNS 被放行时**（系统 DNS 就是路由器），路由器能看到你查询了哪些域名，但看不到真实 IP 与 Anthropic 之间的连接。保护记录里会有“放行局域网 DNS”一条。
- **你自己以 root 身份运行的 setuid 程序**（如 `traceroute`）与代理内核共用放行身份；NetGuard 会在 1 分钟内发现并通知，但不会拦截。
- **虚拟机共享网络（vmnet NAT）**的转发流量会被拦截（不泄露，只是不通）。
- 其他程序（VPN、网络工具）在 pf 里放的放行规则无法被 NetGuard 拦下，因为 NetGuard 从不修改别人的规则；能越过断网保护的放行规则会被报为高危异常并锁定 Claude，`verify` 里也有对应一行。
- 开启 macOS **互联网共享**会替换 `com.apple/*` 锚点，断网规则因此失效；NetGuard 会把它报为高危异常并锁定，但不会去改主规则集。
- FlClash 内核自己的 DIRECT 流量（例如国内直连规则）仍走真实 IP，这一点与 Windows 相同；不过发往 Anthropic 官方网段的流量已被拦截，规则模式也会被当作异常处理。

## CI 实测结果（2026-11-11，GitHub Actions macos-15-arm64，macOS 15.8.2）

单元测试 75 项、真实 pf 集成测试 70 项全部通过，0 失败，0 警告。集成测试在真实内核里验证了：
- 普通用户直连、root 后台程序直连：都被拦截；代理内核（setuid root + 用户组）的 TCP、已连接和未连接 UDP：都被放行；
- 代理内核直连 Anthropic 网段：被拦截；隔离 Claude 时，从 TUN 去 Anthropic 网段也被拦截，代理本身不受影响；
- 回环、局域网网关、TUN 源地址：都被放行；拦截局域网 DNS 的规则确实命中；
- 有其他程序共用代理内核的放行身份联网时，监测能发现它；
- 没有 FlClash 时拒绝开启；enable 中途被杀后自动回滚；模拟重启后，规则在 Python 启动前重新加载；紧急恢复、通过管理员密码框升级、卸载都正常；
- 运行前后 `/etc/pf.conf`、`/etc/hosts`、pf 主规则集和 pf 启用状态完全一致。

## 配置 `/Library/NetGuard/config.json`

修改后执行 `sudo launchctl kickstart -k system/com.netguard.daemon` 生效；如果改了规则相关项，还要再执行一次 `enable`。

| 键 | 默认 | 说明 |
|---|---|---|
| `whitelist` | 安装时从 ClaudeGuard 导入 | 出口白名单，支持 IP 或网段 |
| `check_url` / `claude_check_url` | Cloudflare / claude.ai 的 `/cdn-cgi/trace` | 两个出口检查地址 |
| `tun_v4` / `tun_v6` | `198.18.0.0/16` / `fdfe:dcba:9876::/48` | FlClash 默认的 TUN 地址 |
| `core_names` | `["FlClashCore"]` | 代理内核进程名 |
| `block_lan_dns` | `"auto"` | 局域网 DNS：auto＝能拦就拦，true＝总是拦（开启时 DNS 不通就回滚），false＝不拦 |
| `require_global_mode` | `true` | FlClash 不是全局模式时记为异常 |
| `anthropic_v4` / `anthropic_v6` | 官方网段（2026-11-11 核对） | 来源：platform.claude.com/docs/en/api/ip-addresses |
| `require_claudeguard` | `true` | ClaudeGuard 没在运行时报中危异常 |

## 文件位置

- `/Library/NetGuard/`：程序（root 所有）、`config.json`、`state.json`、`guard.json`、`status.json`、`events.jsonl`、`netguard.log`
- `/Library/LaunchDaemons/com.netguard.daemon.plist`：后台，开机自启
- `/Applications/NetGuard.app`：菜单栏和工作台（安装时在本机编译）；`~/Library/LaunchAgents/com.netguard.menu.plist`
- `/Applications/NetGuard 紧急恢复.command`

## 开发与测试

```bash
cd macos && python3 -m unittest discover -s tests -p 'test_*.py'
```
GitHub Actions（`.github/workflows/macos.yml`）在一次性的 macOS 15 虚拟机上：用系统自带的 Python 3.9 跑单元测试，用 `pfctl -n` 检查规则语法，编译菜单栏程序，然后执行 `ci/integration.sh`。这个脚本会安装 NetGuard、把规则真正加载进内核、逐项检查哪些流量被拦截、哪些被放行，并依次测试回滚、模拟重启后重新加载规则、紧急恢复和卸载，最后确认 pf.conf、hosts 和主规则集都没有被改动。**不要**在自己的 Mac 上运行 `ci/integration.sh`。
