# macOS 真机验收

CI（GitHub Actions 的一次性 macOS 15 虚拟机）已经验证过 pf 规则在真实内核里的行为、各种失败时的回滚、重启后重新加载规则、紧急恢复和卸载（见 workflow 运行记录）。但 CI 虚拟机上没有 FlClash、TUN、Claude，也没有睡眠唤醒，所以下面这些项目只能在你自己的 Mac 上验收。**没做过的项目保持“未运行”**，界面变绿不等于这一项已通过。

每一项都由你本人操作。涉及断开代理的项目，先关闭浏览器和 Claude。

| # | 项目 | 怎么测（安全做法） | 预期 | 状态 |
|---|---|---|---|---|
| 1 | 开启 | `sudo /Library/NetGuard/bin/netguard enable` | 显示“断网保护已开启”，网页正常 | 未运行 |
| 2 | 完整自检 | `sudo /Library/NetGuard/bin/netguard verify` | 全部 ✅，其中“绑定 en0 直连被拦截”为 ✅ | 未运行 |
| 3 | 代理停止 | 关闭浏览器/Claude 后运行 `sudo /Library/NetGuard/bin/netguard drill`（或工作台维护页“运行自动断线演练”）：它自己退出 FlClash、断开 45 秒并采样、再重新打开；3 分钟未恢复会自动急救 | 结论“通过”：断开期间公网请求成功 0 次、网关可达、TUN 消失后 ≤40 秒锁定、网络自动恢复 | 未运行 |
| 4 | 恢复 | 第 3 项结束后（FlClash 已被自动重新打开），在工作台点“解除锁定” | 检查通过后解除；Claude 可以重新打开 | 未运行 |
| 5 | 重启 | 断网保护开启状态下重启电脑 | 登录前后都没有直连；FlClash 自启后网络恢复；180 秒宽限期内不会因为“内核未就绪”而锁定；关机过程中产生的中危锁定在开机检查通过后自动解除（保护记录里有“开机后自动解除”） | 未运行 |
| 6 | 睡眠唤醒 | 合盖 5 分钟后再打开 | 不会误锁（宽限期）；`netguard status` 显示的是新状态 | 未运行 |
| 7 | 切换网络 | Wi‑Fi ↔ 有线 / 手机热点 | 切换后 `verify` 全部 ✅ | 未运行 |
| 8 | 出口不在白名单 | 在 FlClash 切到一个不在白名单的节点 | 20 秒内锁定并结束 Claude；切回来后才能解除 | 未运行 |
| 9 | Claude 隔离 | 锁定期间打开 Claude 桌面版和 `claude` | 2 秒内被结束 | 未运行 |
| 10 | DIRECT 泄露 | 在 FlClash 里把 claude.ai 临时设为 DIRECT，再运行 `curl -m 5 https://claude.ai/cdn-cgi/trace` | 对 Anthropic 官方网段的连接被拒绝，或因出口检查而锁定 | 未运行 |
| 11 | 急救入口 | 双击“NetGuard 紧急恢复” | 规则移除，网络恢复；之后可以重新 `enable` | 未运行 |
| 12 | 菜单栏/工作台 | 查看图标颜色、三个页面；在系统设置里把显示缩放调到更大 | 文字可读，按钮都能点到 | 未运行 |
| 13 | ClaudeGuard 共存 | 运行 `claudeguard doctor`，并确认它的拦截仍然有效 | 两者的 pf 锚点互不影响 | 未运行 |
| 14 | 规则模式 | 在 FlClash 切到“规则”模式，等 30 秒，再切回全局并“解除锁定” | 工作台显示“代理模式：规则 ✗”，20 秒内锁定；切回全局后可解除 | 未运行 |
| 15 | 局域网 DNS | 查看工作台“局域网 DNS”，以及保护记录里有无“放行局域网 DNS” | 能拦截时显示“拦截”；若显示“放行”，记录里说明了原因，且网页能正常打开 | 未运行 |
| 16 | 隔离速度 | 进入真实 IP 模式（向导第 1 步），连续打开 Claude 桌面版 3 次 | 每次在 1 秒内被结束；退出向导第 3 步后可正常打开 | 未运行 |
| 17 | Claude 钩子 | 运行 `ls -l ~/.local/bin/claude`，再看工作台“Claude 钩子” | 指向 ClaudeGuard 的 cli_wrapper.py，工作台显示 ✓ | 未运行 |
| 18 | 自动更新 | 维护页“自动更新”点“立即检查…”（密码框），或运行 `sudo /Library/NetGuard/bin/netguard update now` | 已是最新时显示“已是最新”；有 CI 全过的新版本时安装、自检通过并通知；`netguard update status` 显示结果 | 未运行 |
| 19 | 免密解除锁定 | 锁定状态下在工作台点“解除锁定”；再在终端运行 `/Library/NetGuard/bin/netguard-control release` | 工作台：检查通过才解除，不弹密码框；终端直接运行：被拒绝（“只接受 NetGuard 界面发起的请求”），保持锁定 | 未运行 |
| 20 | 白名单变更 | 断网保护开启时，在工作台添加一个新 IP；之后把白名单删到只剩一项，再尝试删除这最后一项 | 添加后 10 秒内后台就使用新白名单（无需重启后台）；最后一项拒绝删除 | 未运行 |
| 21 | 直连模式开启 | 代理正常时在维护页“代理断开时”选“允许直连”（或 `sudo /Library/NetGuard/bin/netguard proxy-down direct`），然后 `sudo /Library/NetGuard/bin/netguard verify` | 显示“断网保护已开启（直连模式）”；verify 全部 ✅，含“Claude 其他地址拦截表”“Claude 主站解析在 Anthropic 网段内”“绑定 en0 访问拦截表中的地址被拒绝” | 未运行 |
| 22 | 直连模式：关代理 | 先退出 Claude、关闭 claude.ai 网页，再退出 FlClash；然后用浏览器打开一个普通网站，运行 `curl -m 5 https://claude.ai/cdn-cgi/trace`，再试着打开 Claude 桌面版和 `claude` | 普通网站能打开；curl 失败；Claude 桌面版和 `claude` 立即被结束；菜单栏橙色、工作台显示“代理已断开：浏览器等可直连，Claude 已隔离” | 未运行 |
| 23 | 直连模式：代理恢复 | 第 22 项之后重新打开 FlClash，等 20 秒 | 收到“NetGuard：代理已恢复”通知，自动解除隔离，保护记录有一条“代理已恢复：全部检查通过，自动解除”；Claude 可以正常打开 | 未运行 |
| 24 | 退出后清理（取代 ClaudeExitGuard） | 在 Claude Code 里运行一个后台命令（例如 `sleep 600 &`），然后按 ⌘Q 退出 Claude 桌面版，再运行 `pgrep -fl "sleep 600"` | 约 2–4 秒后弹出“Claude 已退出：结束了 N 个残留进程”并有提示音；pgrep 没有输出；工作台“Claude 进程”显示上次清理。通过后可用 ClaudeExitGuard 自带的 `scripts/uninstall.sh` 卸载它 | 未运行 |

本文件是验收**模板**，提交到 Git 的版本保持“未运行”。本机的验收结果、证据文件名和本机路径记在仓库以外的地方，不要提交。

如果任何一项失败，先运行 `netguard events -n 50` 并查看 `/Library/NetGuard/netguard.log`，把输出交给维护者。不要用关闭保护的方式让问题“消失”。
