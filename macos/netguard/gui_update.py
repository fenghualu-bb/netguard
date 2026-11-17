"""Conservative automatic GUI updates. The protection daemon is never replaced here.

Checks run as the desktop user on menu-app launch. Any protection-core change is
queued for a reviewed full upgrade. Only this root-owned helper can install a GUI;
it requires exact-SHA CI, a healthy verified guard, and an unchanged core manifest.
"""
import hashlib
import json
import os
import pathlib
import plistlib
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path('/Library/NetGuard')
APP = pathlib.Path('/Applications/NetGuard.app')
REPO_URLS = {'https://github.com/fenghualu-bb/netguard.git',
             'https://github.com/fenghualu-bb/netguard', 'git@github.com:fenghualu-bb/netguard.git'}
API = 'repos/fenghualu-bb/netguard/'
# Same signature as install.sh: ad-hoc with the hardened runtime, which control.py requires.
CODESIGN = ['/usr/bin/codesign', '--force', '--options', 'runtime', '--sign', '-']

# The same small launch hook is retained when building a newer upstream GUI.
SWIFT_HOOK = r'''
// NETGUARD_SAFE_GUI_UPDATE_V1 — root-owned helper never replaces the guard.
func netguardSafeGUIUpdate(manual: Bool = false) {
    DispatchQueue.global().async {
        let helper = "/Library/NetGuard/bin/netguard-gui-update"
        func run(_ exe: String, _ args: [String]) -> (Bool, String) {
            let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
            let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
            do {
                try p.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
                return (p.terminationStatus == 0, String(data: data, encoding: .utf8) ?? "")
            } catch { return (false, String(describing: error)) }
        }
        let (ok, text) = run(helper, ["prepare"])
        let data = text.data(using: .utf8)
        let result = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
        guard ok, let value = result else {
            if manual { DispatchQueue.main.async { showResult(false, text) } }; return
        }
        guard value["status"] as? String == "ready", let stage = value["stage"] as? String else {
            if manual { DispatchQueue.main.async { showResult(value["status"] as? String == "current", value["message"] as? String ?? text) } }
            return
        }
        DispatchQueue.main.async {
            // Administrative authorization is always the macOS system password dialog.
            let command = shellQuote(helper) + " apply " + shellQuote(stage)
            DispatchQueue.global().async {
                let (installed, output) = run("/usr/bin/osascript", ["-e", "do shell script \"\(command) 2>&1\" with administrator privileges"])
                if !installed || manual { DispatchQueue.main.async { showResult(installed, output) } }
            }
        }
    }
}
'''


def run(args, timeout=60):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or 'command failed')[-1500:])
    return result.stdout


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def atomic_json(path, data):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix='.update-')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
        os.chmod(name, 0o600)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_json(path):
    return json.loads(pathlib.Path(path).read_text())


def user_paths():
    # Root must use the actual console user, never HOME or an untrusted argument.
    uid = os.stat('/dev/console').st_uid if os.geteuid() == 0 else os.getuid()
    if not uid:
        raise RuntimeError('没有桌面用户，暂缓更新')
    account = pwd.getpwuid(uid)
    home = pathlib.Path(account.pw_dir)
    return account, home / 'Library/Application Support/NetGuard/Updates'


def core_changes(names):
    allowed = ('macos/app/', 'macos/tests/')
    docs = {'macos/README.md', 'macos/ACCEPTANCE.md', 'macos/AGENTS.md'}
    return [n for n in names if (n.startswith('macos/') and n not in docs and
                               not n.startswith(allowed)) or n.startswith('.github/workflows/')]


def healthy(status, now=None):
    now = time.time() if now is None else now
    guard = status.get('guard') or {}
    obs = status.get('observations') or {}
    cg = obs.get('claudeguard') or {}
    return (0 <= now - status.get('updated_at', 0) < 45 and
            status.get('killswitch_complete') is True and
            guard.get('enabled') is True and guard.get('lockdown') is False and
            not guard.get('last_findings') and status.get('claude_block') is False and
            obs.get('egress_ok') is True and obs.get('claude_egress_ok') is True and
            obs.get('tun') and obs.get('route') == obs.get('tun') and
            (obs.get('flclash') or {}).get('mode') == 'global' and
            cg.get('fresh') is True and cg.get('protection_enabled') is True and
            cg.get('state') == 'allowed' and
            cg.get('helper_loaded') is True and cg.get('cli_hooked') is not False and
            cg.get('app_path_ok') is not False and cg.get('cli_path_ok') is not False)


def inject_hook(source):
    # Retain the restricted release interface and password-free state refresh in
    # newer upstream GUIs as well; never fall back to changing sudo policy.
    if 'NETGUARD_LOCAL_RELEASE_V1' not in source:
        anchor = '    /// Runs the root CLI through the macOS administrator prompt.'
        if source.count(anchor) != 1:
            raise RuntimeError('新界面权限入口变动，暂缓自动更新')
        methods = '''    // NETGUARD_LOCAL_RELEASE_V1
    func releaseWithoutPassword() {
        runProcess("/Library/NetGuard/bin/netguard-control", ["release"])
    }
    func refreshStatus() { reload() }

'''
        source = source.replace(anchor, methods + anchor)
        source = source.replace('model.admin(["release"])', 'model.releaseWithoutPassword()')
        source = source.replace('model.admin(["refresh"])', 'model.refreshStatus()')
        source = source.replace('Button("刷新检测")', 'Button("刷新状态")')
        source = source.replace('withTitle: "刷新检测…"', 'withTitle: "刷新状态"')
    if 'NETGUARD_SAFE_GUI_UPDATE_V1' in source:
        return source
    launch = 'func applicationDidFinishLaunching(_ notification: Notification) {'
    if source.count(launch) != 1:
        raise RuntimeError('新界面启动入口变动，暂缓自动更新')
    source = source.replace(launch, launch + '\n        netguardSafeGUIUpdate()')
    source, count = re.subn(r'    func update\(\) \{.*?\n    func uninstall\(\)',
                            '    func update() { netguardSafeGUIUpdate(manual: true) }\n\n    func uninstall()',
                            source, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError('新界面更新入口变动，暂缓自动更新')
    return source + '\n' + SWIFT_HOOK


def installed_manifest():
    # Nothing in this manifest is ever replaced by this updater.
    files = [p for p in (ROOT / 'lib').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    files += [p for p in (ROOT / 'bin').iterdir() if p.is_file()]
    files += [ROOT / n for n in ('config.json', 'python-path', 'source.json')]
    files += [p for p in (pathlib.Path('/Library/LaunchDaemons/com.netguard.daemon.plist'),
                         pathlib.Path('/Library/LaunchDaemons/com.netguard.control.plist')) if p.is_file()]
    return {str(p): digest(p) for p in sorted(files)}


def make_policy():
    if os.geteuid() != 0:
        raise RuntimeError('初始化更新策略需要系统管理员授权')
    source = read_json(ROOT / 'source.json')
    base = source['commit']
    if not re.fullmatch('[0-9a-f]{7,40}', base):
        raise RuntimeError('安装版本不明确，不能启用自动更新')
    policy = {'base_commit': base, 'gui_commit': base, 'repo': source['repo'],
              'core_manifest': installed_manifest(), 'created_at': time.time()}
    atomic_json(ROOT / 'gui-update-policy.json', policy)
    os.chmod(ROOT / 'gui-update-policy.json', 0o644)
    return policy


def require_manifest(policy):
    if installed_manifest() != policy['core_manifest']:
        raise RuntimeError('保护组件或配置已改变，保留现有版本，需重新核验更新策略')


def gh_path(home):
    for p in (home / '.local/bin/gh', pathlib.Path('/opt/homebrew/bin/gh'), pathlib.Path('/usr/local/bin/gh')):
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    raise RuntimeError('找不到 gh，保留现有版本')


def ci_passed(sha, gh, prefix=()):
    payload = json.loads(run(list(prefix) + [gh, 'api', API + 'actions/runs?head_sha=' + sha + '&per_page=30']))
    for job in payload.get('workflow_runs', []):
        if (job.get('head_sha') != sha or job.get('name') != 'macOS NetGuard' or
                job.get('head_branch') != 'main' or job.get('event') != 'push' or
                job.get('conclusion') != 'success' or job.get('status') != 'completed'):
            continue
        jobs = json.loads(run(list(prefix) + [gh, 'api', API + 'actions/runs/' + str(job['id']) + '/jobs?per_page=100']))
        good = {j.get('name') for j in jobs.get('jobs', []) if j.get('conclusion') == 'success'}
        if {'Offline tests (system Python 3.9)', 'Real pf integration (disposable VM)'} <= good:
            return job['html_url']
    raise RuntimeError('目标提交尚无完整通过的 macOS 单元和真实 pf CI，保留现有版本')


def prepare():
    if os.geteuid() == 0:
        raise RuntimeError('下载和编译必须由桌面用户执行')
    account, cache = user_paths()
    policy = read_json(ROOT / 'gui-update-policy.json')
    require_manifest(policy)
    repo = policy['repo']
    if run(['/usr/bin/git', '-C', repo, 'remote', 'get-url', 'origin']).strip() not in REPO_URLS:
        raise RuntimeError('更新来源不是指定的 NetGuard 仓库')
    run(['/usr/bin/git', '-C', repo, 'fetch', 'origin', 'main'], timeout=120)
    sha = run(['/usr/bin/git', '-C', repo, 'rev-parse', 'refs/remotes/origin/main']).strip()
    installed = run(['/usr/bin/git', '-C', repo, 'rev-parse', policy['gui_commit'] + '^{commit}']).strip()
    if sha == installed:
        return {'status': 'current', 'message': '当前没有新版本；保护后台持续运行。', 'commit': sha}
    names = run(['/usr/bin/git', '-C', repo, 'diff', '--name-only', '--no-renames', '-z',
                 policy['base_commit'], sha]).split('\0')
    changes = core_changes([n for n in names if n])
    if changes:
        return {'status': 'blocked', 'commit': sha, 'message': '新版本涉及保护组件，已保留当前版本，需审核后完整升级。', 'files': changes}
    if not healthy(read_json(ROOT / 'status.json')):
        return {'status': 'blocked', 'commit': sha, 'message': '保护检查尚未全部正常，暂缓更新。'}
    ci = ci_passed(sha, gh_path(pathlib.Path(account.pw_dir)))
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    stage = pathlib.Path(tempfile.mkdtemp(prefix='candidate-', dir=str(cache)))
    try:
        swift = run(['/usr/bin/git', '-C', repo, 'show', sha + ':macos/app/NetGuardApp.swift'])
        (stage / 'NetGuardApp.swift').write_text(inject_hook(swift))
        info = run(['/usr/bin/git', '-C', repo, 'show', sha + ':macos/app/Info.plist'])
        plistlib.loads(info.encode())
        (stage / 'Info.plist').write_text(info)
        arch = run(['/usr/bin/uname', '-m']).strip()
        run(['/usr/bin/xcrun', 'swiftc', '-O', '-swift-version', '5', '-parse-as-library',
             '-target', arch + '-apple-macos13.0', '-o', stage / 'NetGuard', stage / 'NetGuardApp.swift',
             '-framework', 'AppKit', '-framework', 'SwiftUI'], timeout=180)
        atomic_json(stage / 'candidate.json', {'commit': sha, 'ci': ci,
                    'binary_sha256': digest(stage / 'NetGuard'), 'plist_sha256': digest(stage / 'Info.plist')})
        return {'status': 'ready', 'commit': sha, 'stage': stage.name,
                'message': '界面更新已通过来源、核心兼容性及 CI 检查，等待系统密码框。'}
    except BaseException:
        shutil.rmtree(stage)
        raise


def apply(stage_name):
    if os.geteuid() != 0:
        raise RuntimeError('安装需要系统管理员密码框授权')
    if not re.fullmatch(r'candidate-[A-Za-z0-9_\-]+', stage_name):
        raise RuntimeError('更新目录无效')
    account, cache = user_paths()
    stage = cache / stage_name
    if stage.is_symlink() or stage.resolve().parent != cache.resolve():
        raise RuntimeError('拒绝符号链接更新目录')
    for name in ('NetGuard', 'Info.plist', 'candidate.json'):
        p = stage / name
        if p.is_symlink() or not p.is_file() or p.stat().st_uid != account.pw_uid:
            raise RuntimeError('更新文件所有者或类型异常')
    policy = read_json(ROOT / 'gui-update-policy.json')
    require_manifest(policy)
    data = read_json(stage / 'candidate.json')
    sha = data['commit']
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise RuntimeError('目标版本无效')
    prefix = ['/usr/bin/sudo', '-H', '-u', account.pw_name]
    git = prefix + ['/usr/bin/git', '-C', policy['repo']]
    names = run(git + ['diff', '--name-only', '--no-renames', '-z', policy['base_commit'], sha]).split('\0')
    if core_changes([n for n in names if n]):
        raise RuntimeError('目标版本涉及保护组件，拒绝自动替换')
    ci_passed(sha, gh_path(pathlib.Path(account.pw_dir)), prefix=prefix)
    if not healthy(read_json(ROOT / 'status.json')):
        raise RuntimeError('当前保护检查未全部正常，保留现有版本')
    run([ROOT / 'bin/netguard', 'verify'], timeout=90)
    if digest(stage / 'NetGuard') != data['binary_sha256'] or digest(stage / 'Info.plist') != data['plist_sha256']:
        raise RuntimeError('候选文件已变化，拒绝安装')
    if (stage / 'Info.plist').read_bytes() != (APP / 'Contents/Info.plist').read_bytes():
        raise RuntimeError('应用身份或权限声明发生变化，需审核后升级')
    # Snapshot the candidate into a root-only directory before copying, avoiding
    # executing any script from a user-writable checkout with root privileges.
    with tempfile.TemporaryDirectory(prefix='netguard-gui-', dir=str(ROOT)) as tmp:
        tmp = pathlib.Path(tmp)
        shutil.copyfile(stage / 'NetGuard', tmp / 'candidate')
        if digest(tmp / 'candidate') != data['binary_sha256']:
            raise RuntimeError('候选文件在复制时变化')
        original = APP / 'Contents/MacOS/NetGuard'
        backup = ROOT / ('gui-backup-' + str(time.time_ns()))
        shutil.copy2(original, backup)
        try:
            require_manifest(policy)
            shutil.copyfile(tmp / 'candidate', tmp / 'NetGuard')
            os.chmod(tmp / 'NetGuard', 0o755)
            os.replace(tmp / 'NetGuard', original)
            run(CODESIGN + [APP])
            require_manifest(policy)
            if not healthy(read_json(ROOT / 'status.json')):
                raise RuntimeError('更新时保护状态变化，恢复原界面')
        except BaseException:
            shutil.copy2(backup, original)
            run(CODESIGN + [APP])
            raise
    policy['gui_commit'] = sha
    atomic_json(ROOT / 'gui-update-policy.json', policy)
    os.chmod(ROOT / 'gui-update-policy.json', 0o644)
    # Only the user interface restarts; the guard daemon and pf never stop.
    run(['/bin/launchctl', 'kickstart', '-k', 'gui/%d/com.netguard.menu' % account.pw_uid])
    return {'status': 'installed', 'commit': sha, 'message': '界面已更新；保护后台、规则、配置及本地解锁修复保持原样。'}


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else 'prepare'
    try:
        if command == 'init-policy':
            make_policy(); print('已初始化保守自动更新策略。'); return 0
        result = apply(sys.argv[2]) if command == 'apply' and len(sys.argv) == 3 else prepare()
        if command != 'apply':
            _, cache = user_paths()
            result['checked_at'] = time.time()
            atomic_json(cache / 'update-status.json', result)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        result = {'status': 'blocked', 'message': str(exc), 'checked_at': time.time()}
        if os.geteuid() != 0:
            try:
                _, cache = user_paths(); atomic_json(cache / 'update-status.json', result)
            except Exception:
                pass
        print(json.dumps(result, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    sys.exit(main())
