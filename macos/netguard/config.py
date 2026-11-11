"""Root-owned configuration with validated defaults."""
import copy
import ipaddress
import json
import os

from . import paths, util

# Anthropic's published inbound ranges (platform.claude.com/docs/en/api/ip-addresses,
# checked 2026-11-11). Traffic to them is refused on every path except the TUN, so a
# DIRECT rule in FlClash cannot send Claude traffic out with the real IP.
ANTHROPIC_V4 = ["160.79.104.0/23", "153.61.224.0/22"]
ANTHROPIC_V6 = ["2607:6bc0::/48"]

DEFAULTS = {
    "whitelist": [],
    "check_url": "https://www.cloudflare.com/cdn-cgi/trace",
    "claude_check_url": "https://claude.ai/cdn-cgi/trace",
    # FlClash defaults: tun inet4 198.18.0.1/16, inet6 fdfe:dcba:9876::1/126.
    "tun_v4": "198.18.0.0/16",
    "tun_v6": "fdfe:dcba:9876::/48",
    "core_names": ["FlClashCore"],
    "lan_v4": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
               "100.64.0.0/10", "224.0.0.0/4", "255.255.255.255/32"],
    "lan_v6": ["fe80::/10", "ff00::/8", "fc00::/7"],
    # Windows blocks DNS to the LAN router too. On macOS the system resolver is often the
    # router itself; blocking it would leave "Wi-Fi connected, nothing opens". Opt-in only.
    "block_lan_dns": False,
    "anthropic_v4": ANTHROPIC_V4,
    "anthropic_v6": ANTHROPIC_V6,
    "claude_app_paths": ["/Applications/Claude.app"],
    "require_claudeguard": True,
    # Public addresses used only to prove that a direct physical-interface connection fails.
    "bypass_probe_targets": ["1.1.1.1", "1.0.0.1"],
}


class ConfigError(ValueError):
    pass


def _cidrs(values, version, key):
    if not isinstance(values, list):
        raise ConfigError("%s 必须是列表" % key)
    out = []
    for value in values:
        try:
            net = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            raise ConfigError("%s 含无效网段：%r" % (key, value))
        if net.version != version:
            raise ConfigError("%s 只能是 IPv%d：%r" % (key, version, value))
        out.append(str(net))
    return out


def validate(data):
    cfg = copy.deepcopy(DEFAULTS)
    if data:
        if not isinstance(data, dict):
            raise ConfigError("config.json 顶层必须是对象")
        for key, value in data.items():
            if key in cfg:
                cfg[key] = value
    if not isinstance(cfg["whitelist"], list):
        raise ConfigError("whitelist 必须是列表")
    cfg["whitelist"] = sorted(set(normalize_whitelist_entry(e) for e in cfg["whitelist"]))
    for key, version in (("lan_v4", 4), ("anthropic_v4", 4), ("lan_v6", 6), ("anthropic_v6", 6)):
        cfg[key] = _cidrs(cfg[key], version, key)
    cfg["tun_v4"] = _cidrs([cfg["tun_v4"]], 4, "tun_v4")[0]
    cfg["tun_v6"] = _cidrs([cfg["tun_v6"]], 6, "tun_v6")[0]
    for key in ("check_url", "claude_check_url"):
        if not isinstance(cfg[key], str) or not cfg[key].startswith("https://"):
            raise ConfigError("%s 必须是 https 地址" % key)
    if not cfg["core_names"] or not all(isinstance(n, str) and n and "/" not in n for n in cfg["core_names"]):
        raise ConfigError("core_names 必须是非空的程序名列表")
    if not all(isinstance(p, str) and p.startswith("/") and p.endswith(".app") for p in cfg["claude_app_paths"]):
        raise ConfigError("claude_app_paths 必须是 .app 绝对路径")
    for key in ("block_lan_dns", "require_claudeguard"):
        cfg[key] = bool(cfg[key])
    targets = []
    for value in cfg["bypass_probe_targets"]:
        addr = ipaddress.ip_address(str(value))
        if addr.is_private or addr.is_loopback:
            raise ConfigError("bypass_probe_targets 必须是公网地址")
        targets.append(str(addr))
    cfg["bypass_probe_targets"] = targets
    return cfg


def normalize_whitelist_entry(entry):
    text = str(entry).strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ConfigError("白名单含无效 IP：%r" % (entry,))


def ip_in_whitelist(ip, whitelist):
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    for entry in whitelist:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def load(path=None):
    data = util.read_json(path or paths.CONFIG, None)
    if data is None and os.path.exists(path or paths.CONFIG):
        raise ConfigError("config.json 无法解析")
    return validate(data or {})


def save(cfg, path=None):
    clean = validate(cfg)
    util.write_json(path or paths.CONFIG, clean, mode=0o644)
    return clean


def claudeguard_whitelist(user):
    """allowed_ips from the console user's ClaudeGuard config, if any."""
    import pwd
    try:
        home = pwd.getpwnam(user).pw_dir
    except (KeyError, TypeError):
        return []
    data = util.read_json(os.path.join(home, ".config", "claudeguard", "config.json"), {}) or {}
    out = []
    for entry in data.get("allowed_ips", []) if isinstance(data, dict) else []:
        try:
            out.append(normalize_whitelist_entry(entry))
        except ConfigError:
            continue
    return sorted(set(out))


def dumps_redacted(cfg):
    return json.dumps(cfg, ensure_ascii=False, indent=2, sort_keys=True)
