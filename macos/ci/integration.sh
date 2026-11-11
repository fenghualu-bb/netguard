#!/bin/bash
# Real-pf integration test. Runs ONLY on disposable GitHub Actions macOS runners:
#   sudo -E bash macos/ci/integration.sh
# It installs NetGuard, loads the kill-switch rules into the real kernel, probes what
# is blocked and what passes, exercises rollback / boot re-apply / recovery / uninstall,
# and proves that /etc/pf.conf, /etc/hosts and the main pf ruleset are unchanged.
set -u
if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    echo "integration.sh 只在 GitHub Actions 的一次性 macOS 虚拟机上运行，不要在自己的 Mac 上运行。"
    exit 2
fi
[ "$(id -u)" = "0" ] || { echo "需要 sudo"; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
MACOS="$(dirname "$HERE")"
RUNNER="${SUDO_USER:?run with sudo from the runner account}"
ANCHOR='com.apple/zz.NetGuard'
ROOT=/Library/NetGuard
WORK=/tmp/ngci
PASS=0; FAIL=0; WARN=0; MATRIX_TOKEN=""

ok()   { PASS=$((PASS + 1)); echo "  PASS  $*"; }
bad()  { FAIL=$((FAIL + 1)); echo "  FAIL  $*"; echo "::error::$*"; }
warn() { WARN=$((WARN + 1)); echo "  WARN  $*"; echo "::warning::$*"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else bad "$desc"; fi; }
section() { echo; echo "=== $* ==="; }

cleanup() {
    /sbin/pfctl -a "$ANCHOR" -F rules >/dev/null 2>&1
    [ -n "$MATRIX_TOKEN" ] && /sbin/pfctl -X "$MATRIX_TOKEN" >/dev/null 2>&1
    local t
    t=$(cat "$ROOT/pf-token" 2>/dev/null) && [ -n "$t" ] && /sbin/pfctl -X "$t" >/dev/null 2>&1
    /sbin/ifconfig lo0 -alias 198.18.0.1 >/dev/null 2>&1
    return 0
}
trap cleanup EXIT

net_ok() { [ "$(curl -s -o /dev/null -m 15 -w '%{http_code}' https://www.apple.com/)" != "000" ]; }
anchor_empty() { [ -z "$(/sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null)" ]; }
anchor_loaded() { /sbin/pfctl -a "$ANCHOR" -sr 2>/dev/null | grep -q ng_block_all; }
token_live() {
    local t; t=$(cat "$ROOT/pf-token" 2>/dev/null)
    [ -n "$t" ] && /sbin/pfctl -s References 2>/dev/null | awk -v t="$t" '$1 ~ /^[0-9]+$/ { for (i = 2; i <= NF; i++) if ($i == t) f = 1 } END { exit !f }'
}
state_has() { grep -q "$1" "$ROOT/state.json" 2>/dev/null; }
py() { "$(cat "$ROOT/python-path")" -I -B -c "import sys; sys.path.insert(0, '$ROOT/lib'); $1"; }

labels() { /sbin/pfctl -a "$ANCHOR" -s labels 2>/dev/null | awk '{ p[$1] += $3 } END { for (k in p) print k, p[k] }' | sort; }
delta() {  # delta <before> <after> <label>
    local b a
    b=$(printf '%s\n' "$1" | awk -v l="$3" '$1 == l { print $2 }'); a=$(printf '%s\n' "$2" | awk -v l="$3" '$1 == l { print $2 }')
    echo $(( ${a:-0} - ${b:-0} ))
}

# ------------------------------------------------------------------------------
section "0. 基线"
PF_CONF_BEFORE=$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)
HOSTS_BEFORE=$(shasum -a 256 /etc/hosts | cut -d' ' -f1)
MAIN_BEFORE=$(/sbin/pfctl -sr 2>/dev/null)
PFSTATUS_BEFORE=$(/sbin/pfctl -s info 2>/dev/null | awk '/^Status:/ { print $2 }')
echo "pf 状态：${PFSTATUS_BEFORE}；macOS $(sw_vers -productVersion) $(uname -m)；runner=$RUNNER gid=$(id -g "$RUNNER")"
echo "主规则集："; printf '%s\n' "$MAIN_BEFORE" | sed 's/^/    /'
check "安装前网络可用" net_ok

# ------------------------------------------------------------------------------
section "1. 安装"
if bash "$MACOS/install.sh" --ci; then ok "install.sh 成功"; else bad "install.sh 失败"; fi
check "后台已注册" launchctl print system/com.netguard.daemon
sleep 3
check "status.json 已生成" test -f "$ROOT/status.json"
check "NetGuard.app 已编译" test -x /Applications/NetGuard.app/Contents/MacOS/NetGuard
check "紧急恢复入口存在" test -x "/Applications/NetGuard 紧急恢复.command"
check "安装没有加载任何断网规则" anchor_empty
check "安装后网络可用" net_ok
check "代码目录 root 所有、他人不可写" bash -c "[ \"\$(stat -f '%Su %Sp' $ROOT/lib/netguard/service.py)\" = 'root -rw-r--r--' ]"
check "普通用户能读 status" sudo -u "$RUNNER" /Library/NetGuard/bin/netguard status

# ------------------------------------------------------------------------------
section "2. 没有 FlClash 时必须拒绝开启（防止断网的关键）"
"$ROOT/bin/netguard" whitelist add 203.0.113.10 >/dev/null
out=$("$ROOT/bin/netguard" enable 2>&1); rc=$?
echo "$out" | sed 's/^/    /'
check "enable 被拒绝" [ "$rc" -ne 0 ]
check "拒绝原因指向 FlClash" grep -q "FlClash" <<<"$out"
check "拒绝后没有规则" anchor_empty
check "拒绝后没有 pf token" test ! -s "$ROOT/pf-token"
check "拒绝后网络可用" net_ok

# ------------------------------------------------------------------------------
section "3. 真实 pf 规则矩阵"
mkdir -p "$WORK"
clang -O -o "$WORK/prober" "$HERE/prober.c" || bad "编译 prober 失败"
chmod 755 "$WORK" "$WORK/prober"
cp "$WORK/prober" "$WORK/prober-core"
chown root:admin "$WORK/prober-core"; chmod 4750 "$WORK/prober-core"   # same as FlClash authorizeCore
GID=$(id -g "$RUNNER")
GW=$(route -n get default 2>/dev/null | awk '/gateway:/ { print $2 }')
IFACE=$(route -n get default 2>/dev/null | awk '/interface:/ { print $2 }')
echo "默认网关：$GW 接口：$IFACE"
MATRIX_TOKEN=$(py "
from netguard import config, pfrules
pf = pfrules.PF()
pf.load(pfrules.render(config.validate({}), 0, $GID))
print(pf.acquire_token(None))")
echo "矩阵 token：$MATRIX_TOKEN"
/sbin/pfctl -a "$ANCHOR" -sr | sed 's/^/    /'
check "规则已加载" anchor_loaded
check "pf 已启用" bash -c "/sbin/pfctl -s info | grep -q 'Status: Enabled'"
L0=$(labels); [ -n "$L0" ] || warn "pfctl -s labels 无输出：只能用连接结果判断"

probe_case() {  # probe_case <desc> <expect OK|FAIL> <label-that-must-grow> <runner|core|root> <prober args...>
    local desc="$1" expect="$2" label="$3" who="$4"; shift 4
    local before after res d
    before=$(labels)
    case "$who" in
        runner) res=$(sudo -u "$RUNNER" "$WORK/prober" "$@" 2>&1) ;;
        core)   res=$(sudo -u "$RUNNER" "$WORK/prober-core" "$@" 2>&1) ;;
        root)   res=$("$WORK/prober" "$@" 2>&1) ;;
    esac
    after=$(labels)
    d=$(delta "$before" "$after" "$label")
    echo "    [$who] prober $* -> ${res}；$label +$d"
    if [ "$expect" != "-" ]; then
        case "$res" in
            OK*) [ "$expect" = "OK" ] && ok "${desc}：连接结果 OK" || bad "${desc}：应被拦截却连上了" ;;
            *)   [ "$expect" = "FAIL" ] && ok "${desc}：连接被拦截" || bad "${desc}：应放行却失败（${res}）" ;;
        esac
    fi
    if [ -n "$L0" ]; then
        if [ "$d" -gt 0 ]; then ok "${desc}：命中规则 $label"; else
            if [ "$expect" = "-" ]; then warn "${desc}：未命中 $label"; else bad "${desc}：未命中规则 $label"; fi
        fi
    fi
}

probe_case "普通用户直连公网（模拟 Claude 绕过代理）" FAIL ng_block_all runner 1.1.1.1 443 3000
probe_case "root 后台直连公网（wheel 组，不应放行）" FAIL ng_block_all root 1.1.1.1 443 3000
probe_case "代理内核（setuid root + 用户组）TCP" OK ng_core core 1.1.1.1 443 5000
probe_case "代理内核 UDP（已连接套接字）" - ng_core core -c 1.1.1.1 53
probe_case "代理内核 UDP（未连接套接字 sendto，Hysteria/TUIC 类协议）" - ng_core core -u 1.1.1.1 53
probe_case "代理内核直连 Anthropic 网段（DIRECT 规则泄露）" FAIL ng_anthropic core 160.79.104.10 443 3000
probe_case "回环地址" - ng_loopback runner 127.0.0.1 9 1000
if [ -n "$GW" ]; then
    probe_case "局域网网关" - ng_lan runner "$GW" 80 2000
fi
if /sbin/ifconfig lo0 alias 198.18.0.1/32 2>/dev/null; then
    probe_case "TUN 源地址流量放行（模拟进入 TUN 的流量）" - ng_tun runner -b 198.18.0.1 1.1.1.1 443 1500
    /sbin/ifconfig lo0 -alias 198.18.0.1 2>/dev/null
else
    warn "无法添加 198.18.0.1 别名，跳过 TUN 源地址用例"
fi
/sbin/pfctl -a "$ANCHOR" -F rules >/dev/null 2>&1
/sbin/pfctl -X "$MATRIX_TOKEN" >/dev/null 2>&1; MATRIX_TOKEN=""
check "矩阵清理后规则为空" anchor_empty
check "矩阵清理后网络可用" net_ok

# ------------------------------------------------------------------------------
section "4. enable 中途死掉：后台自动回滚"
py "
from netguard import service, util
s = service.Service()
st = s.read_state()
st.update({'pending': {'deadline': s.clock() + 120, 'prev': {'killswitch': False, 'core_gid': None}},
           'killswitch': True, 'core_gid': $GID})
s.write_state(st)
st['rules_fp'] = s.apply_rules($GID)
s.write_state(st)
print('已模拟：规则已加载、pending 未完成、enable 进程已退出')"
check "模拟后规则在位" anchor_loaded
for _ in $(seq 1 30); do anchor_empty && ! state_has '"killswitch": true' && break; sleep 1; done
check "后台已回滚：规则为空" anchor_empty
check "后台已回滚：killswitch=false" bash -c "! grep -q '\"killswitch\": true' $ROOT/state.json"
check "后台已回滚：token 已释放" test ! -s "$ROOT/pf-token"
check "保护记录有 rollback" grep -q '"type": "rollback"' "$ROOT/events.jsonl"
check "回滚后网络可用" net_ok

# ------------------------------------------------------------------------------
section "5. 重启后在 Python 之前重新加载规则（netguard-boot）"
py "
from netguard import service
s = service.Service()
st = s.read_state()
st.update({'killswitch': True, 'core_gid': $GID, 'pending': None})
st['rules_fp'] = s.apply_rules($GID)
s.write_state(st)
s.pf.flush(); s.pf.release_token(s.read_token())
print('已模拟重启：pf 里的规则和引用都没了，anchor.rules 与 state 保留')"
check "模拟重启后规则为空" anchor_empty
launchctl kickstart -k system/com.netguard.daemon
for _ in $(seq 1 15); do anchor_loaded && break; sleep 1; done
check "后台启动后规则已恢复" anchor_loaded
check "后台启动后 pf 引用有效" token_live
check "规则生效时绑定 $IFACE 直连被拦截" bash -c "! curl -s -o /dev/null -m 5 --interface ${IFACE:-en0} https://1.1.1.1/"
check "规则生效时普通用户直连被拦截" bash -c "! sudo -u $RUNNER curl -s -o /dev/null -m 5 https://1.1.1.1/"

section "6. 紧急恢复脚本（不需要网络、不依赖 Python）"
/Library/NetGuard/bin/netguard-recover
check "恢复后规则为空" anchor_empty
check "恢复后 killswitch=false" bash -c "grep -q '\"killswitch\": false' $ROOT/state.json"
check "恢复后后台重新运行" launchctl print system/com.netguard.daemon
sleep 12
check "恢复后后台不再加载规则" anchor_empty
check "恢复后网络可用" net_ok

# ------------------------------------------------------------------------------
section "7. 卸载"
bash "$ROOT/uninstall.sh" --purge
check "卸载后没有规则" anchor_empty
check "卸载后没有文件" test ! -e "$ROOT"
check "卸载后没有 LaunchDaemon" test ! -e /Library/LaunchDaemons/com.netguard.daemon.plist
check "卸载后没有 App" test ! -e /Applications/NetGuard.app

section "8. 全局不变量"
check "/etc/pf.conf 未改动" [ "$(shasum -a 256 /etc/pf.conf | cut -d' ' -f1)" = "$PF_CONF_BEFORE" ]
check "/etc/hosts 未改动" [ "$(shasum -a 256 /etc/hosts | cut -d' ' -f1)" = "$HOSTS_BEFORE" ]
check "pf 主规则集未改动" [ "$(/sbin/pfctl -sr 2>/dev/null)" = "$MAIN_BEFORE" ]
check "pf 启用状态恢复为安装前（${PFSTATUS_BEFORE}）" \
    [ "$(/sbin/pfctl -s info 2>/dev/null | awk '/^Status:/ { print $2 }')" = "$PFSTATUS_BEFORE" ]
check "结束时网络可用" net_ok

echo
echo "结果：PASS=$PASS FAIL=$FAIL WARN=$WARN"
[ "$FAIL" -eq 0 ]
