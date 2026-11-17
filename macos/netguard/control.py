"""A console-user-only release request, delegated to the existing root CLI.

No shell, arbitrary arguments, configuration writes, or new release logic. The
root-owned server only executes `netguard release`, and only for a request made by the
installed NetGuard menu bar app (verify_caller); all other commands, and a release from any
other program, still require the macOS administrator dialog. Refreshing the GUI is a local read.
"""
import ctypes
import json
import os
import pathlib
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
import time

ROOT = pathlib.Path('/Library/NetGuard')
SOCKET = ROOT / 'control.sock'
CLI = ROOT / 'bin/netguard'
APP = pathlib.Path('/Applications/NetGuard.app')
APP_EXE = APP / 'Contents/MacOS/NetGuard'
MAX_REQUEST = 256
MAX_RESPONSE = 65536
SOL_LOCAL = 0
LOCAL_PEERPID = 0x002
CALLER_REFUSED = '只接受 NetGuard 界面发起的解除请求'


class ControlError(RuntimeError):
    pass


def peer_uid(connection):
    """Kernel credentials, never a uid claimed in the request payload."""
    if sys.platform == 'darwin':
        libc = ctypes.CDLL(None, use_errno=True)
        call = libc.getpeereid
        call.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        call.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if call(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise ControlError('无法核验本地连接身份')
        return uid.value
    if sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED'):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        return struct.unpack('3i', raw)[1]
    raise ControlError('系统不支持安全的本地身份核验')


def peer_pid(connection):
    """Kernel-reported pid of the connected client (macOS LOCAL_PEERPID)."""
    if sys.platform != 'darwin':
        raise ControlError('系统不支持安全的本地身份核验')
    return struct.unpack('i', connection.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0]


def process_path(pid):
    """Executable of a running process as the kernel sees it (not argv[0], which is caller-chosen)."""
    libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    buf = ctypes.create_string_buffer(4096)
    if libproc.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(4096)) <= 0:
        raise ControlError('无法读取本地请求进程的程序路径')
    return buf.value.decode('utf-8', 'surrogateescape')


def parent_pid(pid):
    result = subprocess.run(['/bin/ps', '-o', 'ppid=', '-p', str(int(pid))], capture_output=True,
                            text=True, timeout=10, env={'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C'})
    text = result.stdout.strip()
    if result.returncode != 0 or not text.isdigit():
        raise ControlError('无法读取本地请求进程的父进程')
    return int(text)


def root_owned(paths):
    """Every path is root-owned, not a symlink and not writable by group or others.

    /Applications is writable by admin users, so an admin account could move NetGuard.app aside
    and drop its own bundle there; such a replacement is user-owned and is refused here.
    """
    for path in paths:
        info = os.lstat(str(path))
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ControlError('NetGuard 界面文件的所有者或权限异常，请重新运行 install.sh')


def hardened_runtime(app):
    """The app must be signed with the hardened runtime, so DYLD_INSERT_LIBRARIES cannot load
    foreign code into it (install.sh signs it ad-hoc with --options runtime)."""
    result = subprocess.run(['/usr/bin/codesign', '--display', '--verbose=1', str(app)], capture_output=True,
                            text=True, timeout=20, env={'PATH':'/usr/bin:/bin', 'LANG':'C', 'LC_ALL':'C'})
    match = re.search(r'flags=0x[0-9a-f]+\(([^)]*)\)', result.stdout + result.stderr)
    return result.returncode == 0 and bool(match) and 'runtime' in match.group(1).split(',')


def verify_caller(connection, pid_of=peer_pid, path_of=process_path, parent_of=parent_pid,
                  ownership=root_owned, hardened=hardened_runtime, own_pid=os.getpid):
    """Only the NetGuard menu bar app may request a release.

    The GUI runs /Library/NetGuard/bin/netguard-control, which execs the same interpreter as this
    server, so the client is that interpreter and its parent is the installed, root-owned,
    hardened NetGuard.app. Other programs of the same account (scripts, coding agents) are refused;
    they still have `sudo netguard release` with the administrator password.
    """
    pid = pid_of(connection)
    if path_of(pid) != path_of(own_pid()):
        raise ControlError(CALLER_REFUSED)
    if path_of(parent_of(pid)) != str(APP_EXE):
        raise ControlError(CALLER_REFUSED)
    ownership([APP, APP / 'Contents', APP / 'Contents/MacOS', APP_EXE])
    if not hardened(APP):
        raise ControlError('NetGuard 界面缺少 hardened runtime 签名，请重新运行 install.sh')


def console_uid():
    try:
        uid = os.stat('/dev/console').st_uid
        owner = json.loads((ROOT / 'source.json').read_text())['user']
        installed_uid = pwd.getpwnam(owner).pw_uid
        return uid if uid != 0 and uid == installed_uid else None
    except (OSError, ValueError, KeyError):
        return None


def protected_directory(path):
    info = pathlib.Path(path).lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ControlError('本地控制接口的父目录不安全')


def read_message(connection, limit):
    data = b''
    while b'\n' not in data:
        chunk = connection.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            raise ControlError('本地请求不完整')
        data += chunk
        if len(data) > limit:
            raise ControlError('本地请求过长')
    message, extra = data.split(b'\n', 1)
    if extra:
        raise ControlError('每次连接只允许一个请求')
    try:
        return json.loads(message.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise ControlError('本地请求格式无效')


def validate_request(message):
    if (not isinstance(message, dict) or set(message) != {'version', 'action'} or
            type(message['version']) is not int or message['version'] != 1 or
            message['action'] != 'release'):
        raise ControlError('此接口只接受解除锁定，不允许其他操作或参数')


def execute_release():
    # The CLI retains its state lock, dual-egress/whitelist checks, TUN, mode,
    # ClaudeGuard, pf integrity checks, and the verified isolation probe fix.
    # Do not kill a mutating CLI mid-command on a client timeout/disconnect.
    result = subprocess.run([str(CLI), 'release'], capture_output=True, text=True,
                            cwd='/private/tmp', env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin',
                                                     'LANG':'C', 'LC_ALL':'C'})
    output = (result.stdout + result.stderr).strip()
    return {'ok':result.returncode == 0, 'code':result.returncode, 'output':output[:16000]}


class Server:
    def __init__(self, path=SOCKET, uid_reader=console_uid, credentials=peer_uid,
                 executor=execute_release, directory_check=protected_directory, clock=time.monotonic,
                 caller_check=verify_caller):
        self.path = pathlib.Path(path)
        self.uid_reader = uid_reader
        self.credentials = credentials
        self.caller_check = caller_check
        self.executor = executor
        self.directory_check = directory_check
        self.clock = clock
        self.listener = None
        self.owner = None
        self.last_request = None
        self.identity = None

    def sync_owner(self):
        uid = self.uid_reader()
        owner = 0 if uid is None else uid
        if self.owner != owner:
            os.chmod(self.path, 0o600)
            os.chown(self.path, owner, 0 if os.geteuid() == 0 else -1)
            self.owner = owner

    def start(self):
        self.directory_check(self.path.parent)
        if self.path.exists() or self.path.is_symlink():
            if not stat.S_ISSOCK(self.path.lstat().st_mode):
                raise ControlError('拒绝覆盖已有的非 socket 文件')
            self.path.unlink()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            old_mask = os.umask(0o077)
            try:
                self.listener.bind(str(self.path))
            finally:
                os.umask(old_mask)
            self.identity = self.path.lstat().st_ino
            self.sync_owner()
            self.listener.listen(4)
            self.listener.settimeout(1)
        except BaseException:
            self.close()
            raise

    def handle(self, connection):
        connection.settimeout(3)
        try:
            uid = self.credentials(connection)
            expected = self.uid_reader()
            if expected is None or uid != expected:
                raise ControlError('只允许当前桌面登录用户请求解除锁定')
            self.caller_check(connection)
            message = read_message(connection, MAX_REQUEST)
            validate_request(message)
            if self.uid_reader() != uid:
                raise ControlError('桌面用户已切换，拒绝旧会话请求')
            now = self.clock()
            if self.last_request is not None and now - self.last_request < 3:
                raise ControlError('请求过于频繁，请稍后再试')
            self.last_request = now
            response = self.executor()
        except Exception as exc:
            response = {'ok':False, 'code':2, 'output':str(exc)}
        try:
            connection.sendall(json.dumps(response, ensure_ascii=False).encode('utf-8') + b'\n')
        except OSError:
            pass  # disconnect never cancels, retries, or weakens the release checks
        finally:
            connection.close()

    def serve(self, stop=None):
        self.start()
        try:
            while stop is None or not stop.is_set():
                self.sync_owner()
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                self.handle(connection)
        finally:
            self.close()

    def close(self):
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        try:
            if self.identity is not None and self.path.lstat().st_ino == self.identity:
                self.path.unlink()
        except FileNotFoundError:
            pass


def request_release(path=SOCKET, credentials=peer_uid, directory_check=protected_directory):
    path = pathlib.Path(path)
    directory_check(path.parent)
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
        raise ControlError('本地接口权限不正确或当前用户未登录桌面')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(150)
        connection.connect(str(path))
        if credentials(connection) != 0:
            raise ControlError('本地服务不是 root，拒绝发送请求')
        connection.sendall(b'{"version":1,"action":"release"}\n')
        response = read_message(connection, MAX_RESPONSE)
    if not isinstance(response, dict) or type(response.get('ok')) is not bool:
        raise ControlError('本地服务返回无效结果')
    return response


def main():
    try:
        if sys.argv[1:] == ['serve']:
            if os.geteuid() != 0:
                raise ControlError('安装本地服务需要一次系统管理员授权')
            Server().serve()
            return 0
        if sys.argv[1:] == ['release']:
            response = request_release()
            print(response['output'])
            return 0 if response['ok'] else 1
        raise ControlError('仅支持 serve 或 release；不接受任意命令')
    except Exception as exc:
        print('操作未完成（保护未被此接口关闭）：' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
