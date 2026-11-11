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
| 自动防护 | 每 10 秒检查一次：普通出口和 claude.ai 出口是否在白名单、断网规则是否完整、FlClash 内核是否以 root 运行、TUN 是否在线、ClaudeGuard 是否在运行。连续 2 次异常就**锁定**。 |
| 锁定 | 立即结束 Claude 桌面版和 Claude Code，之后每 2 秒检查一次，重新打开也会被结束，直到你在工作台点“解除锁定”。解除前会重新做全部检查，有一项不通过就拒绝解除。 |
| 宽限期 | 开机、登录、睡眠唤醒后 180 秒内，中危异常（内核/TUN/ClaudeGuard 还没起来）只记录一条，不锁定；高危异常照常锁定。与 Windows 1.3.5 相同。 |
| 真实 IP 模式 | 需要临时不用代理时，先“隔离 Claude”，等出口回到白名单再退出。 |
| 界面 | 菜单栏盾牌图标（绿=当前检查通过，黄=保护未开，橙=有异常，红=锁定/规则不完整，灰=后台没运行），工作台窗口分“概览 / 保护记录 / 维护”三页。系统通知会提示锁定和“代理未就绪、已阻断直连”。 |

锁定策略按你的要求与 Windows 版一致：中危异常（内核、TUN、ClaudeGuard 未就绪）在宽限期外连续出现 2 次也会锁定。

## 为什么这次不会像上次那样断网

上次 Mac 上的那次尝试具体装了什么，现在已经无法查清（已恢复出厂）。可以确定的是，“连得上 Wi‑Fi 但什么都打不开、重启也没用”通常是这几种情况之一。针对每一种的防护如下：

| 可能的原因 | 本项目的防护 |
|---|---|
| 断网规则把代理内核自己也拦了，形成死循环 | 开启前检查 FlClash 内核**确实以 root 运行**（TUN 已授权），才生成放行它的规则；内核没授权时拒绝开启。CI 在真实 macOS 上验证过：这条放行规则只放行 root + 用户组，不放行普通程序和 root 后台程序。 |
| 改了 `/etc/pf.conf` 或重载了主规则集，开机后反复生效 | **从不**写 `/etc/pf.conf`，**从不**重载主规则集，**从不**执行 `pfctl -d` / `-F all`。规则只放在独立锚点 `com.apple/zz.NetGuard` 里。CI 会对比安装前后的 pf.conf、hosts 和主规则集。 |
| DNS 被拦（系统 DNS 是路由器，没走 TUN） | 默认**放行**局域网 DNS（`block_lan_dns=false`）。开启后会自检 DNS，失败就自动回滚。 |
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

## 卸载

```bash
sudo bash /Library/NetGuard/uninstall.sh          # 会保留一份配置和保护记录
sudo bash /Library/NetGuard/uninstall.sh --purge  # 全部删除
```

## 与 Windows 版的差异

| | Windows | macOS |
|---|---|---|
| 防火墙 | WFP，最高权重子层 | pf，独立锚点 `com.apple/zz.NetGuard`；先默认拦截，再由后续规则放行（后匹配的规则生效） |
| 放行代理内核 | 按程序路径（FlClashCore.exe） | 按套接字身份：root + 你的用户组（FlClash 授权后的内核正是这个身份） |
| 隔离 Claude | 按程序加 WFP 拦截规则 + 结束进程 | pf 不能按程序过滤，所以改为结束进程，并每 2 秒检查一次、重新打开也结束 |
| Anthropic 网段 | 无 | 只要不是从 TUN 出去，一律拒绝 |
| 局域网 DNS | 拦截 | 默认放行（`block_lan_dns` 可改为拦截）；拦截很容易造成“连得上 Wi‑Fi 但打不开网页” |
| 规则持久化 | WFP 持久规则 | pf 规则重启后会消失，由 LaunchDaemon 在开机时（Python 启动前）用纯 shell 重新加载 |

## 已知限制（如实说明）

- **只读的状态检查不能证明不会泄露。** 绿色只表示“当前检查通过（未做断线测试）”。停掉代理、睡眠唤醒、切换 Wi‑Fi/有线等情况要按 [ACCEPTANCE.md](ACCEPTANCE.md) 在真机上验收。
- **你以 root 身份运行的其他 setuid 程序**（例如 `traceroute`）也会被当作代理内核放行。Claude、浏览器以及其他普通程序都不受影响。
- **虚拟机的共享网络（vmnet NAT）**经过转发的流量不带 TUN 源地址，断网保护开启时会被拦截（不会泄露，只是不通）。Docker Desktop 和 Parallels 的用户态网络不受影响。
- 开启 macOS 的**互联网共享**会替换 `com.apple/*` 锚点，断网规则因此失效。NetGuard 会把这种情况报为高危异常并锁定，但不会去改主规则集。
- FlClash 内核的 DIRECT 流量（例如国内直连规则）仍然走真实 IP，这一点和 Windows 一样。只有发往 Anthropic 官方网段的流量被硬拦截；claude.ai 走 Cloudflare 的那部分只能靠出口检查发现。
- 基于 UDP 的代理协议（Hysteria2、TUIC 等），内核套接字的身份识别结果见 CI 报告。如果识别失败，`enable` 的自检会因为“代理出口不可用”而自动回滚，不会断网。

## 配置 `/Library/NetGuard/config.json`

修改后执行 `sudo launchctl kickstart -k system/com.netguard.daemon` 生效；如果改了规则相关项，还要再执行一次 `enable`。

| 键 | 默认 | 说明 |
|---|---|---|
| `whitelist` | 安装时从 ClaudeGuard 导入 | 出口白名单，支持 IP 或网段 |
| `check_url` / `claude_check_url` | Cloudflare / claude.ai 的 `/cdn-cgi/trace` | 两个出口检查地址 |
| `tun_v4` / `tun_v6` | `198.18.0.0/16` / `fdfe:dcba:9876::/48` | FlClash 默认的 TUN 地址 |
| `core_names` | `["FlClashCore"]` | 代理内核进程名 |
| `block_lan_dns` | `false` | 是否拦截发往局域网的 DNS |
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
