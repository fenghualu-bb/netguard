"""Restricted local delegation, tested with real Unix credentials and fake CLI."""
import json
import os
import pathlib
import socket
import stat
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from fakes import HERE
from netguard import control


class ProtocolTests(unittest.TestCase):
    def exchange(self, payload, uid=None, console=None, executor=None, clock=lambda:100, caller=None):
        left,right=socket.socketpair()
        self.addCleanup(left.close);self.addCleanup(right.close)
        calls=[]
        action=executor or (lambda:calls.append('release') or {'ok':True,'code':0,'output':'checked release'})
        server=control.Server(uid_reader=console or (lambda:501), credentials=lambda s:501 if uid is None else uid,
                              executor=action,clock=clock,caller_check=caller or (lambda s:None))
        right.sendall(payload)
        right.shutdown(socket.SHUT_WR)
        server.handle(left)
        result=control.read_message(right,control.MAX_RESPONSE)
        return result,calls,server

    def test_only_exact_release_request_reaches_executor(self):
        result,calls,_=self.exchange(b'{"version":1,"action":"release"}\n')
        self.assertTrue(result['ok']);self.assertEqual(calls,['release'])

    def test_other_actions_extra_args_and_malformed_requests_are_rejected(self):
        requests=[b'not json\n',b'[]\n',b'{"version":true,"action":"release"}\n',
                  b'{"version":2,"action":"release"}\n',b'{"version":1,"action":"release","uid":0}\n',
                  b'{"version":1,"action":"release","args":["--skip-checks"]}\n',
                  b'{"version":1,"action":"release"}\n{"action":"disable"}\n', b'x'*300+b'\n']
        for action in ('disable','recover','guard-off','whitelist','isolate','refresh','/bin/sh','release; id'):
            requests.append(json.dumps({'version':1,'action':action}).encode()+b'\n')
        for request in requests:
            with self.subTest(request=request):
                result,calls,_=self.exchange(request)
                self.assertFalse(result['ok']);self.assertEqual(calls,[])

    def test_other_user_and_no_console_user_cannot_release(self):
        for uid,console in ((502,lambda:501),(0,lambda:501),(501,lambda:None)):
            with self.subTest(uid=uid):
                result,calls,_=self.exchange(b'{"version":1,"action":"release"}\n',uid=uid,console=console)
                self.assertFalse(result['ok']);self.assertEqual(calls,[])

    def test_fast_user_switch_during_request_is_rejected(self):
        identities=iter([501,502])
        result,calls,_=self.exchange(b'{"version":1,"action":"release"}\n',console=lambda:next(identities))
        self.assertFalse(result['ok']);self.assertEqual(calls,[])

    def test_cli_refusal_is_preserved_without_retry_or_force(self):
        calls=[]
        def refused():calls.append(1);return {'ok':False,'code':1,'output':'仍有异常，保持锁定：claude.ai 出口未取得'}
        result,_,_=self.exchange(b'{"version":1,"action":"release"}\n',executor=refused)
        self.assertFalse(result['ok']);self.assertIn('保持锁定',result['output']);self.assertEqual(len(calls),1)

    def test_rate_limit_never_executes_second_command(self):
        result,calls,server=self.exchange(b'{"version":1,"action":"release"}\n')
        left,right=socket.socketpair();self.addCleanup(left.close);self.addCleanup(right.close)
        right.sendall(b'{"version":1,"action":"release"}\n')
        server.handle(left)
        result=control.read_message(right,control.MAX_RESPONSE)
        self.assertFalse(result['ok']);self.assertEqual(calls,['release'])

    def test_fixed_cli_argv_and_no_shell_or_password_storage(self):
        completed=subprocess.CompletedProcess([],1,'still locked\n','reason\n')
        with mock.patch.object(control.subprocess,'run',return_value=completed) as run:
            response=control.execute_release()
        self.assertFalse(response['ok'])
        args,kw=run.call_args
        self.assertEqual(args[0],['/Library/NetGuard/bin/netguard','release'])
        self.assertNotIn('shell',kw)
        self.assertNotIn('timeout',kw)  # client disconnect never kills a mutating CLI
        self.assertEqual(kw['cwd'],'/private/tmp')
        self.assertEqual(set(kw['env']),{'PATH','LANG','LC_ALL'})

    def test_real_kernel_peer_credentials(self):
        a,b=socket.socketpair()
        try:
            self.assertEqual(control.peer_uid(a),os.getuid())
            self.assertEqual(control.peer_uid(b),os.getuid())
        finally:a.close();b.close()


class SocketTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=pathlib.Path(self.tmp.name)/'control.sock'

    def test_root_owned_parent_is_required(self):
        with self.assertRaises(control.ControlError):control.protected_directory(self.path.parent)
        link=self.path.parent/'link';link.symlink_to(self.path.parent,target_is_directory=True)
        with self.assertRaises(control.ControlError):control.protected_directory(link)

    def test_only_installation_owner_at_console_is_authorized(self):
        root=self.path.parent
        (root/'source.json').write_text('{"user":"fixture-owner"}')
        with mock.patch.object(control,'ROOT',root),mock.patch.object(control.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=501)):
            with mock.patch.object(control.os,'stat',return_value=SimpleNamespace(st_uid=501)):
                self.assertEqual(control.console_uid(),501)
            with mock.patch.object(control.os,'stat',return_value=SimpleNamespace(st_uid=502)):
                self.assertIsNone(control.console_uid())
        (root/'source.json').write_text('{}')
        with mock.patch.object(control,'ROOT',root):self.assertIsNone(control.console_uid())

    def test_server_never_overwrites_regular_file_or_symlink(self):
        self.path.write_text('keep')
        server=control.Server(path=self.path,directory_check=lambda p:None)
        with self.assertRaises(control.ControlError):server.start()
        self.assertEqual(self.path.read_text(),'keep')
        self.path.unlink();self.path.symlink_to(self.path.parent/'missing')
        with self.assertRaises(control.ControlError):server.start()
        self.assertTrue(self.path.is_symlink())

    def test_socket_permissions_and_client_root_verification(self):
        uid=os.getuid()
        server=control.Server(path=self.path,uid_reader=lambda:uid,directory_check=lambda p:None)
        server.start();self.addCleanup(server.close)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
        # The test server is unprivileged; production clients must reject it.
        with self.assertRaises(control.ControlError):
            control.request_release(path=self.path,directory_check=lambda p:None)

    def test_real_socket_request_roundtrip_with_only_test_server_credential_override(self):
        uid=os.getuid();stop=threading.Event()
        server=control.Server(path=self.path,uid_reader=lambda:uid,directory_check=lambda p:None,
                              executor=lambda:{'ok':True,'code':0,'output':'all checks retained'},
                              caller_check=lambda s:None)
        server.start()
        def serve_one():
            connection,_=server.listener.accept();server.handle(connection)
        worker=threading.Thread(target=serve_one);worker.start()
        try:
            result=control.request_release(path=self.path,directory_check=lambda p:None,credentials=lambda s:0)
            self.assertTrue(result['ok']);self.assertEqual(result['output'],'all checks retained')
        finally:worker.join(4);server.close()
        self.assertFalse(worker.is_alive())

    def test_real_socket_from_a_plain_process_is_refused_by_default(self):
        # No override of the caller check: this test process is not NetGuard.app, so the
        # production server refuses it even though the uid is the console user's.
        uid=os.getuid();calls=[]
        server=control.Server(path=self.path,uid_reader=lambda:uid,directory_check=lambda p:None,
                              executor=lambda:calls.append(1) or {'ok':True,'code':0,'output':'released'})
        server.start()
        def serve_one():
            connection,_=server.listener.accept();server.handle(connection)
        worker=threading.Thread(target=serve_one);worker.start()
        try:
            result=control.request_release(path=self.path,directory_check=lambda p:None,credentials=lambda s:0)
            self.assertFalse(result['ok']);self.assertIn(control.CALLER_REFUSED,result['output'])
        finally:worker.join(4);server.close()
        self.assertEqual(calls,[])


class CallerTests(unittest.TestCase):
    """Only the installed, root-owned, hardened NetGuard.app may request a release."""
    PY='/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python'

    def check(self, client=None, parent=None, owned=True, hardened=True):
        paths={1000:client or self.PY, 900:parent or str(control.APP_EXE), 1:self.PY}
        def ownership(items):
            self.assertEqual([str(p) for p in items][-1],str(control.APP_EXE))
            if not owned:raise control.ControlError('owner')
        control.verify_caller(None,pid_of=lambda c:1000,path_of=paths.__getitem__,parent_of=lambda pid:900,
                              ownership=ownership,hardened=lambda app:hardened,own_pid=lambda:1)

    def test_gui_launched_helper_is_accepted(self):
        self.check()

    def test_other_callers_are_refused(self):
        cases={'shell script / agent':dict(parent='/bin/zsh'),
               'Terminal':dict(parent='/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal'),
               'copy of the app elsewhere':dict(parent='/Users/a/Applications/NetGuard.app/Contents/MacOS/NetGuard'),
               'other interpreter':dict(client='/opt/homebrew/bin/python3'),
               'user-owned replacement bundle':dict(owned=False),
               'app without hardened runtime':dict(hardened=False)}
        for name,kw in cases.items():
            with self.subTest(name):
                with self.assertRaises(control.ControlError):self.check(**kw)

    def test_ownership_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'NetGuard'
            path.write_text('x')
            with self.assertRaises(control.ControlError):control.root_owned([path])  # owned by the test user

    def test_codesign_flags_parsing(self):
        def fake(flags,rc=0):
            return subprocess.CompletedProcess([],rc,'','Executable=/x\nCodeDirectory v=20500 size=651 flags=%s hashes=14+2\n'%flags)
        for out,expected in ((fake('0x10002(adhoc,runtime)'),True),(fake('0x2(adhoc)'),False),
                             (fake('0x10002(adhoc,runtime)',rc=1),False),(fake('none'),False)):
            with mock.patch.object(control.subprocess,'run',return_value=out):
                self.assertEqual(control.hardened_runtime(control.APP),expected)

    def test_real_kernel_peer_pid_and_path(self):
        a,b=socket.socketpair()
        try:
            self.assertEqual(control.peer_pid(a),os.getpid())
            self.assertEqual(control.process_path(os.getpid()),control.process_path(control.peer_pid(b)))
            self.assertEqual(control.parent_pid(os.getpid()),os.getppid())
        finally:a.close();b.close()
