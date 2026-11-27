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
| 锁定 / 隔离 | 立即结束 Claude 桌面版、Claude Code，**以及它们启动的全部子进程**（shell、node/python MCP 服务、开发服务器等，父进程退出后也继续跟踪），之后由独立线程**每 0.25 秒**检查一次并直接强制结束（与 Windows Stop-Process -Force 相同），重新打开也会被结束；同时在 TUN 内也拒绝 Claude：Anthropic 官方网段连 TUN 也拒绝；FlClash 用 fake-ip 时 Claude 域名解析到的是 198.18.x.x 代理地址，看不到真实网段，所以后台还会向 FlClash 查询 Claude 常用域名的代理地址，放进 pf 地址表 `ng_claude` 一并拒绝（每 60 秒刷新）。直到你在工作台点“解除锁定”。解除前会重新做全部检查，有一项不通过就拒绝解除。 |
| 宽限期 | 开机、登录、睡眠唤醒后 180 秒内，中危异常（内核/TUN/ClaudeGuard 还没起来）只记录一条，不锁定；高危异常照常锁定。与 Windows 1.3.5 相同。 |
| 关机锁定自动解除 | 关机或重启时，macOS 会先退出 FlClash 和 ClaudeGuard，再停止 NetGuard 后台，后台因此会在关机过程中触发一次锁定。如果这次锁定**只由中危异常引起**，并且发生在本次开机前 10 分钟内，开机后后台会反复做与“解除锁定”完全相同的检查（两个出口都在白名单、断网规则完整、内核和 TUN 正常、ClaudeGuard 在运行），全部通过才自动解除，并留下记录。高危锁定（出口不在白名单、规则不完整）仍然必须手动解除。 |
| 真实 IP 模式 | 工作台里有三步向导（与 Windows 相同）：隔离 Claude → 处理你的事情 → 核对出口回到白名单后退出。 |
| 局域网 DNS | 默认 `auto`：开启断网保护时先**拦截**发往路由器的 DNS（与 Windows 相同）；如果这台 Mac 的系统 DNS 就是路由器、拦了就无法解析，则自动放行并记录。之后换了 Wi‑Fi、DNS 变得不可用时，后台也会自动放行，**绝不让你失去 DNS**。 |
| 代理断开时（可选） | 默认“整机断网”。可改为“允许直连”：代理一断，浏览器等程序用真实 IP 正常上网；Claude 在第一次发现时就被隔离（开机宽限期内也一样，后台每 3 秒看一次 TUN），代理恢复且全部检查通过后自动解除。Anthropic 官方网段和 Claude 其他已知地址（静态资源、CDN、用户内容、统计上报，表 `ng_direct`，每 10 分钟经代理用 DoH 解析一次，代理断开时用系统 DNS 补充）不走代理一律拒绝；同时核对 claude.ai 等主站仍解析在 Anthropic 网段内，不在就加入拦截表并锁定。见下方“代理断开时允许直连”。 |
| 退出后清理（来自 ClaudeExitGuard） | Claude 桌面版退出后，结束它留下的辅助进程、内置 Claude Code 和它们启动的子进程；默认也结束单独运行的 Claude Code（`claude_cleanup`：`full` / `desktop` / `off`）。先 SIGTERM，1 秒后仍在再 SIGKILL，每次发信号前核对 PID、启动时间和程序路径，防止误杀复用了 PID 的其他程序；桌面版运行时一律放行；更新程序 ShipIt 不打断；只处理当前桌面用户自己的进程。菜单栏会弹出约 12 秒的提醒并播放提示音，保护记录里有一条“清理 Claude 残留”。 |
| 识别 Claude | 按内核报告的程序真实路径识别（不看命令行文字，参数里写什么都骗不过），再沿真实进程树跟踪子孙进程。进程表直接从内核读取（libproc），读一次约 3 毫秒，比启动一次 `ps`（约 25 毫秒）省得多。 |
| 放行身份监测 | 每分钟检查是否有其他程序以“root + 你的用户组”身份联网（与 FlClash 内核共用放行身份），发现就记录并通知。Windows 版没有这项检查。 |
| 界面 | 菜单栏盾牌图标（绿=当前检查通过，黄=保护未开，橙=有异常或真实 IP 模式，红=锁定/规则不完整，灰=后台没运行）。工作台与 Windows 布局一致：概览（当前出口、出口 IP、自动防护、ClaudeGuard、FlClash、断网保护、最近操作）、保护记录（可筛选）、维护（白名单、自动防护、完整自检、修复 ClaudeGuard、更新、卸载、日志、急救）。系统通知会提示锁定、代理未就绪、DNS 放行和放行身份被占用。 |

锁定策略按你的要求与 Windows 版一致：中危异常（内核、TUN、ClaudeGuard 未就绪）在宽限期外连续出现 2 次也会锁定。出口不在白名单比 Windows 更严：第一次发现就锁定。

## 为什么不会把 Mac 弄断网

本项目最初就是因为一次失败的尝试：某个断网方案让 Mac “连得上 Wi‑Fi 但什么都打不开、重启也没用”，最后只能恢复出厂。这种情况通常是下面几种原因之一。针对每一种的防护如下：

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
- **ClaudeGuard**：上游 macOS 版（[ivblz/ClaudeGuard](https://github.com/ivblz/ClaudeGuard)；v1 为 MIT 许可，v2 起为 GPL-3.0），已加入白名单 IP

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

先看 [`macos/upstream/claudeguard.json`](upstream/claudeguard.json)：这是 NetGuard 已验证兼容的 ClaudeGuard 版本。

- `"kind": "pkg"`：下载其中 `url` 指向的 `ClaudeGuard.pkg`（NetGuard 仓库 Releases 里的镜像，SHA-256 见 `sha256`），双击安装即可。之后 NetGuard 的自动更新会跟随新的已验证版本。
- `"kind": "source"`（目前是 v1 `61b61e1`）：上游在 2026-11-26 重写了提交历史，这个提交已不在上游分支上，只能按完整提交号取：

```bash
git clone https://github.com/ivblz/ClaudeGuard.git ~/ClaudeGuard
cd ~/ClaudeGuard && git fetch origin 61b61e11a4e05d86a75213abecceb13d80e8acbf && git checkout FETCH_HEAD
./install.sh
```
安装时它会问是否把当前 IP 加入白名单：**只有在代理已连上时**才回答“是”。

> ClaudeGuard 61b61e1 找不到新版官方原生 Claude Code（每个版本是 `~/.local/share/claude/versions/<版本号>` 这样的单个文件），`claudeguard doctor` 会显示 `Hands off to: NOT FOUND`，`claude` 命令无法启动。NetGuard 的 `install.sh` 会自动打一个**只加一行搜索路径**的兼容补丁：打补丁前后都校验文件哈希，文件不是这个版本就拒绝修改，并保留备份；也可以用 `--revert` 还原。重装 ClaudeGuard 后，在工作台维护页点“修复 ClaudeGuard”即可重新打上。

**3. 获取本仓库**（公开仓库，不需要登录）

```bash
git clone https://github.com/fenghualu-bb/netguard.git ~/netguard
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
sudo /Library/NetGuard/bin/netguard proxy-down direct   # 代理断开时允许直连（block = 整机断网，默认）
sudo /Library/NetGuard/bin/netguard cleanup desktop     # 退出后清理：full / desktop / off
```
工作台里的“刷新状态”只读取后台已写出的最新状态，不需要密码；后台仍每 10 秒检查一次。
“解除锁定”通过一次管理员授权安装的受限本地服务，请求原有 `netguard release`：双出口、白名单、TUN、
ClaudeGuard 和规则完整性检查保持不变，有一项不通过就保持锁定。该接口仅接受当前桌面登录用户的解除请求，
使用内核身份核验，不接受其他命令或任意参数。它还核对**发起请求的程序**：必须是已安装的
`/Applications/NetGuard.app`（root 所有、以 hardened runtime 签名，无法用 `DYLD_INSERT_LIBRARIES` 注入）。
同一账户下的其他程序（脚本、终端、Codex / Claude Code 等代理）直接运行 `netguard-control release` 会被拒绝，
需要用 `sudo /Library/NetGuard/bin/netguard release` 并输入密码。剩余风险：已获得“辅助功能”权限的程序可以
模拟点击工作台按钮。
关闭保护、修改白名单、卸载等其他管理员操作仍使用系统密码框。不会保存密码或修改 sudoers。

白名单修改（工作台或 `netguard whitelist`）在 10 秒内被后台读取，不需要重启后台。断网保护开启时，
不能删除最后一个白名单 IP；白名单若被清空（例如手工编辑 config.json），后台会立即锁定 Claude。

本地接口为 `/Library/NetGuard/control.sock`（仅桌面用户可访问，模式 0600），由 root 的
`com.netguard.control` LaunchDaemon 提供，程序位于 root 所有的安装目录。
服务不可用时明确报错，不回退到跳过检查或关闭保护；CLI 的原有 root 命令权限不变。

## 代理断开时允许直连（可选）

默认的“整机断网”最安全：代理一断，整台 Mac 只剩局域网。如果你希望关掉代理后还能用浏览器上网，可以在工作台维护页“代理断开时”选“允许直连”，或运行 `sudo /Library/NetGuard/bin/netguard proxy-down direct`。切换要在代理正常时进行：它会重新开启断网保护并自检，自检失败就自动恢复原设置。

开启后：

- **代理正常时**：和以前一样，流量走 TUN，出口白名单、全局模式等检查照常。
- **代理断开时**：浏览器等程序用真实 IP 直连。Claude 第一次被发现就隔离（桌面版、Claude Code 及其子进程被结束，重新打开也会被结束），真实出口不再探测。发往 Anthropic 官方网段（claude.ai、claude.com、anthropic.com、api.anthropic.com 都在其中，2026-11-17 核对）和 `ng_direct` 表中地址的连接，不走代理一律拒绝，浏览器打开 claude.ai 也不通。
- **代理恢复后**：所有解除锁定检查（两个出口在白名单、TUN、全局模式、ClaudeGuard、规则完整）通过后自动解除隔离并通知。因其他原因（比如出口不在白名单）造成的锁定仍须手动解除。
- **自检**：开启和 `verify` 时，把一个测试地址临时加入 `ng_direct`，确认绑定物理网卡去这个地址的连接被拒绝，然后立即移除。不会向 Anthropic 发任何请求。

这个模式失去的是“整台电脑绝不用真实 IP”这一层；Claude 本身的保护基本不变。剩余风险：

1. 代理断开时，其他对地区敏感的服务会看到你的真实 IP。
2. 浏览器里开着的 claude.ai 页面，后台仍可能请求列表外的第三方服务（统计、登录、支付）。关代理前先退出 Claude、关掉 claude.ai 标签页。
3. 状态页（status.claude.com）和 anthropic.ai 故意不拦：它们在 CloudFront/AWS 的共享地址上，拦了会误伤其他网站，而且跟账号无关。
4. 按地域返回不同地址的 CDN：代理断开时后台会用系统 DNS 再解析一次补进拦截表，但第一次解析前有一个很短的空档。
5. 断线演练（`drill`）只用于整机断网模式；直连模式请按 ACCEPTANCE.md 第 21–23 项验收。

## 与 ClaudeExitGuard 的关系

“Claude 退出监控”（ClaudeExitGuard）的识别和清理逻辑已经并入 NetGuard 后台：同一套识别引擎同时负责隔离和退出后清理，由 root 后台执行，不会被普通程序关掉，而且不会出现两个工具重复扫描。确认 NetGuard 新版工作正常（ACCEPTANCE.md 第 24 项）后，可以用 ClaudeExitGuard 自带的 `scripts/uninstall.sh` 卸载它，它的处理记录会保留。两者同时运行也不会互相误杀，只是重复做同一件事。

## 自动更新与上游跟随

目标：NetGuard 自己保持最新，并且不会因为 ClaudeGuard、FlClash、Claude 或 macOS 更新而突然不能用。

**NetGuard 自动更新**（root 服务 `com.netguard.updater`，每 6 小时检查一次）

- 只安装 [fenghualu-bb/netguard](https://github.com/fenghualu-bb/netguard) `main` 的最新提交，而且要同时满足：它已经是 `main` 最新提交满 24 小时（从这台 Mac 第一次看到它算起），两项 CI（离线测试、真实 pf 集成测试）都在这个提交上通过，并且改动了 macOS 部分（只改 Windows 或文档的提交只记录不安装）。
- 按提交号下载源码到 root 专属目录，用其中的 `install.sh` 安装，然后自检：新版本在运行、断网规则完整、后台和本地接口都在运行。
- 自检不通过：自动恢复本次安装前的备份（程序、命令和界面），这个提交记为坏版本、不再重试。安装在改动文件之前就失败时，只重新启动后台，不会回退到更旧的版本。
- 装好、回滚都会发通知；工作台“维护 → 自动更新”显示最近一次结果，可以关闭或“立即检查”（跳过 24 小时等待，CI 仍须通过）。
- 命令：`sudo /Library/NetGuard/bin/netguard update status|check|now|enable|disable`；记录在 `/Library/NetGuard/update-state.json`，安装日志在 `/Library/NetGuard/updates/`。
- 信任边界：能推送到这个仓库 `main` 的人，就能让代码装到这台 Mac 上。请保护好 GitHub 账号（开两步验证）。

**ClaudeGuard 跟随已验证版本**

- [`macos/upstream/claudeguard.json`](upstream/claudeguard.json) 记录已验证的版本。每天的 [上游兼容性工作流](../.github/workflows/upstream.yml) 拿 ClaudeGuard 最新发布版的源码跑 NetGuard 的兼容测试；通过后把原版安装包和完整源码（GPL-3.0）镜像到本仓库的 Releases（校验 SHA-256），再开一个更新这个文件的 PR。
- PR 合并、`main` 的 CI 通过后，Mac 的自动更新会用 `installer` 安装这个版本，并确认它 2 分钟内正常运行；没能正常运行就停止重试并通知你。镜像意味着上游删提交、重写历史都不影响已验证的版本。
- 目前固定在你在用的 v1（`61b61e1`），所以不会自动换成 v2。v1 → v2 是大版本（GPL-3.0、新增代理模式），合并那个 PR 前请先看它的发布说明。NetGuard 已兼容 v2：它在代理网卡上的放行规则不会再被当成绕过，代理模式会被明确报告为不兼容。

**每天自动核对上游**（GitHub Actions，失败会开 issue，GitHub 会发邮件给你）

| 项目 | 检查内容 |
|---|---|
| ClaudeGuard 最新发布 | NetGuard 读取的文件和字段仍在；它的 pf 规则不会被当成绕过；Claude Code 能被识别（原生或经 NetGuard 补丁） |
| FlClash 最新发布 | 源码里仍有 NetGuard 依赖的内核名、数据目录、TUN 地址和端口配置项 |
| Anthropic | claude.ai 等主站仍解析在配置的官方网段内，这些网段仍在官方页面上 |
| 最新 macOS 镜像 | 全部单元测试 |

**运行时适应**：FlClash 更新后内核的 TUN 授权会失效，NetGuard 会明确提示“FlClash 刚从 x 更新到 y，请重新授权”；内核改名、TUN 地址改变、配置里端口为 0（FlClash 0.9.4 起由运行时决定）都能识别或明确指出。

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
| 隔离 Claude | WFP 按程序断网 + 结束进程 | 独立线程每 0.25 秒强制结束 Claude 及其全部子进程 + 隔离期间 Anthropic 网段及 Claude 域名的 fake-ip 地址连 TUN 也拒绝 + ClaudeGuard 的 hosts 拦截与启动前检查 | 等价（机制不同，见限制） |
| 识别代理内核 | 按程序路径 | 按 root + 用户组，**另加**每分钟监测有无其他程序共用该身份 | 等价（多一层监测） |
| 关机过程中产生的误锁 | 需手动解除 | 开机后检查全部通过自动解除 | **Mac 更强** |
| 开启失败 / 中途被杀 | 自动回滚 | 自动回滚 + 后台 10 秒内回滚中途被杀的操作 | **Mac 更强** |
| 断网急救 | 无专门入口 | 双击“NetGuard 紧急恢复”（无需网络和 Python） | **Mac 更强** |
| 工作台 | 概览 / 记录 / 维护、真实 IP 向导、修复 ClaudeGuard、更新/重装 | 同上，另有菜单栏图标与系统通知 | 等价或更多 |

## 已知限制（如实说明）

- **只读的状态检查不能证明不会泄露。** 绿色只表示“当前检查通过（未做断线测试）”。停代理、睡眠唤醒、切换网络要按 [ACCEPTANCE.md](ACCEPTANCE.md) 在真机上验收。
- **隔离机制不同**：macOS 的 pf 不能按程序拦截，所以隔离靠“独立线程每 0.25 秒强制结束 Claude 及其子进程”。锁定时，Claude Code 帮你启动的开发服务器、后台命令也会一起被结束。隔离期间，经 TUN 发往 Claude 常用域名（claude.ai、claude.com、anthropic.com 的主要子域，列表见 `netguard/claude.py`）的连接也会被拒绝，浏览器打开 claude.ai 同样不通。列表以外的子域名不在其中，要靠 ClaudeGuard 的 hosts 拦截和启动前检查兜底，所以 ClaudeGuard 默认是必需的。FlClash 内核未运行时无法查询，地址表保持上一次的内容。
- **隔离期间的出口核验**：为避免隔离规则拦住 NetGuard 自己的 `claude.ai` 检查、导致永远不能解除，隔离期间通过 FlClash 已有的本地 SOCKS 通道访问同一个 HTTPS 检查地址。只接受配置中的 mixed/socks 端口，并核对监听者确实是获授权的 root FlClash 内核；不能确认时保持隔离。普通出口仍独立经过 TUN 检查，双出口白名单、TUN、全局模式、ClaudeGuard 和防火墙完整性检查仍须通过后才解除锁定；不提前清空隔离表，不修改系统代理。解除后恢复经 TUN 的常规检查。
- **开机最早的几秒**：Windows 的规则由系统在开机最早阶段加载；Mac 由 LaunchDaemon 加载，最早一两秒内系统后台程序可能先联网。要做到和 Windows 一样早，只能修改 `/etc/pf.conf`，而这正是上次让 Mac 无法恢复的高风险做法，所以刻意不做。这时你还没登录，Claude 不可能在运行。
- **局域网 DNS 被放行时**（系统 DNS 就是路由器），路由器能看到你查询了哪些域名，但看不到真实 IP 与 Anthropic 之间的连接。保护记录里会有“放行局域网 DNS”一条。
- **你自己以 root 身份运行的 setuid 程序**（如 `traceroute`）与代理内核共用放行身份；NetGuard 会在 1 分钟内发现并通知，但不会拦截。
- **虚拟机共享网络（vmnet NAT）**的转发流量会被拦截（不泄露，只是不通）。
- 其他程序（VPN、网络工具）在 pf 里放的放行规则无法被 NetGuard 拦下，因为 NetGuard 从不修改别人的规则；能越过断网保护的放行规则会被报为高危异常并锁定 Claude，`verify` 里也有对应一行。
- 开启 macOS **互联网共享**会替换 `com.apple/*` 锚点，断网规则因此失效；NetGuard 会把它报为高危异常并锁定，但不会去改主规则集。
- FlClash 内核自己的 DIRECT 流量（例如国内直连规则）仍走真实 IP，这一点与 Windows 相同；不过发往 Anthropic 官方网段的流量已被拦截，规则模式也会被当作异常处理。

## CI 实测结果（2026-11-17，提交 fd2ad1e，GitHub Actions macos-15-arm64，macOS 15.8.2）

单元测试 215 项、真实 pf 集成测试 106 项全部通过，0 失败，0 警告。每次推送都会重新运行，最新结果以 Actions 页面为准。集成测试在真实内核里验证了：
- 普通用户直连、root 后台程序直连：都被拦截；代理内核（setuid root + 用户组）的 TCP、已连接和未连接 UDP：都被放行；
- 代理内核直连 Anthropic 网段：被拦截；隔离 Claude 时，从 TUN 去 Anthropic 网段也被拦截，代理本身不受影响；
- 回环、局域网网关、TUN 源地址：都被放行；拦截局域网 DNS 的规则确实命中；
- 有其他程序共用代理内核的放行身份联网时，监测能发现它；
- 没有 FlClash 时拒绝开启；enable 中途被杀后自动回滚；模拟重启后，规则在 Python 启动前重新加载；紧急恢复、通过管理员密码框升级、卸载都正常；
- 直连模式（`proxy_down=direct`）：普通程序直连放行；直连 Anthropic 网段和 `ng_direct` 表中的地址被拦（root 也一样）；经 TUN 访问放行，隔离时经 TUN 也被拦；自检用的临时地址加入后立即被拦、移除后恢复；表内容能被精确替换和清空；
- 运行前后 `/etc/pf.conf`、`/etc/hosts`、pf 主规则集和 pf 启用状态完全一致。

## 配置 `/Library/NetGuard/config.json`

后台每次检查（10 秒内）都会读取修改，无需重启后台；文件格式错误时继续使用原配置并写入日志。如果改了规则相关项（网段、DNS 等），还要再执行一次 `enable`。

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
| `proxy_down` | `"block"` | 代理断开时：`block` 整机断网；`direct` 允许直连且立即隔离 Claude（用 `netguard proxy-down` 切换，会自检） |
| `claude_cleanup` | `"full"` | Claude 桌面版退出后：`full` 清理残留并结束单独运行的 Claude Code；`desktop` 只清理桌面版残留；`off` 不清理 |

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
