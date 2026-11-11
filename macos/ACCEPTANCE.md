# macOS 真机验收

CI（GitHub Actions 的一次性 macOS 15 虚拟机）已经验证过 pf 规则在真实内核里的行为、各种失败时的回滚、重启后重新加载规则、紧急恢复和卸载（见 workflow 运行记录）。但 CI 虚拟机上没有 FlClash、TUN、Claude，也没有睡眠唤醒，所以下面这些项目只能在你自己的 Mac 上验收。**没做过的项目保持“未运行”**，界面变绿不等于这一项已通过。

每一项都由你本人操作。涉及断开代理的项目，先关闭浏览器和 Claude。

| # | 项目 | 怎么测（安全做法） | 预期 | 状态 |
|---|---|---|---|---|
| 1 | 开启 | `sudo /Library/NetGuard/bin/netguard enable` | 显示“断网保护已开启”，网页正常 | 未运行 |
| 2 | 完整自检 | `sudo /Library/NetGuard/bin/netguard verify` | 全部 ✅，其中“绑定 en0 直连被拦截”为 ✅ | 未运行 |
| 3 | 代理停止 | 关闭浏览器/Claude 后，在 FlClash 里关掉 TUN（或退出 FlClash），然后运行 `curl -m 5 https://www.apple.com` | curl 失败（不会退回直连）；局域网路由器管理页仍能打开；约 20 秒后 Claude 被锁定并弹出通知 | 未运行 |
| 4 | 恢复 | 重新打开 FlClash 的 TUN，在工作台点“解除锁定” | 检查通过后解除；Claude 可以重新打开 | 未运行 |
| 5 | 重启 | 断网保护开启状态下重启电脑 | 登录前后都没有直连；FlClash 自启后网络恢复；180 秒宽限期内不会因为“内核未就绪”而锁定 | 未运行 |
| 6 | 睡眠唤醒 | 合盖 5 分钟后再打开 | 不会误锁（宽限期）；`netguard status` 显示的是新状态 | 未运行 |
| 7 | 切换网络 | Wi‑Fi ↔ 有线 / 手机热点 | 切换后 `verify` 全部 ✅ | 未运行 |
| 8 | 出口不在白名单 | 在 FlClash 切到一个不在白名单的节点 | 20 秒内锁定并结束 Claude；切回来后才能解除 | 未运行 |
| 9 | Claude 隔离 | 锁定期间打开 Claude 桌面版和 `claude` | 2 秒内被结束 | 未运行 |
| 10 | DIRECT 泄露 | 在 FlClash 里把 claude.ai 临时设为 DIRECT，再运行 `curl -m 5 https://claude.ai/cdn-cgi/trace` | 对 Anthropic 官方网段的连接被拒绝，或因出口检查而锁定 | 未运行 |
| 11 | 急救入口 | 双击“NetGuard 紧急恢复” | 规则移除，网络恢复；之后可以重新 `enable` | 未运行 |
| 12 | 菜单栏/工作台 | 查看图标颜色、三个页面；在系统设置里把显示缩放调到更大 | 文字可读，按钮都能点到 | 未运行 |
| 13 | ClaudeGuard 共存 | 运行 `claudeguard doctor`，并确认它的拦截仍然有效 | 两者的 pf 锚点互不影响 | 未运行 |

如果任何一项失败，先运行 `netguard events -n 50` 并查看 `/Library/NetGuard/netguard.log`，把输出交给维护者。不要用关闭保护的方式让问题“消失”。
