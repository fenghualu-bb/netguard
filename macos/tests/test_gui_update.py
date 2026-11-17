"""No network or pf access: automatic GUI updates must leave the guard untouched."""
import copy
import json
import os
import pathlib
import pwd
import tempfile
import unittest
from unittest import mock

from fakes import HERE
from netguard import gui_update as gu


def safe_status():
    return {'updated_at':1000, 'killswitch_complete':True, 'claude_block':False,
            'guard':{'enabled':True,'lockdown':False,'last_findings':[]},
            'observations':{'egress_ok':True,'claude_egress_ok':True,'tun':'utun5','route':'utun5',
                            'flclash':{'mode':'global'},
                            'claudeguard':{'state':'allowed','fresh':True,'protection_enabled':True,'helper_loaded':True,
                                           'cli_hooked':True,'app_path_ok':True,'cli_path_ok':True}}}


class UpdateGateTests(unittest.TestCase):
    def test_protection_changes_require_review(self):
        for name in ('macos/netguard/service.py','macos/netguard/pfrules.py','macos/netguard/probes.py',
                     'macos/install.sh','macos/bin/netguard','macos/launchd/com.netguard.daemon.plist',
                     '.github/workflows/macos.yml'):
            self.assertEqual(gu.core_changes([name]),[name])
        self.assertEqual(gu.core_changes(['macos/app/NetGuardApp.swift','macos/tests/test_gui_update.py',
                                         'macos/README.md','README.md']),[])

    def test_missing_or_unhealthy_observation_defers_update(self):
        self.assertTrue(gu.healthy(safe_status(),1005))
        self.assertFalse(gu.healthy({},1005))
        for path, value in ((('updated_at',),950),(('updated_at',),1100),
                            (('killswitch_complete',),False),(('claude_block',),True),
                            (('guard','lockdown'),True),(('guard','enabled'),False),
                            (('guard','last_findings'),['unknown exit']),
                            (('observations','egress_ok'),False),(('observations','claude_egress_ok'),False),
                            (('observations','route'),'en0'),(('observations','flclash','mode'),'rule'),
                            (('observations','claudeguard','helper_loaded'),False),
                            (('observations','claudeguard','fresh'),False),
                            (('observations','claudeguard','state'),'offline'),
                            (('observations','claudeguard','protection_enabled'),False),
                            (('observations','claudeguard','cli_hooked'),False),
                            (('observations','claudeguard','app_path_ok'),False)):
            with self.subTest(path=path):
                status=safe_status(); dest=status
                for part in path[:-1]: dest=dest[part]
                dest[path[-1]]=value
                self.assertFalse(gu.healthy(status,1005))

    def test_ci_requires_exact_sha_push_main_and_both_successful_jobs(self):
        sha='a'*40
        run={'head_sha':sha,'name':'macOS NetGuard','head_branch':'main','event':'push',
             'conclusion':'success','status':'completed','id':42,'html_url':'https://example.test/run/42'}
        jobs={'jobs':[{'name':'Offline tests (system Python 3.9)','conclusion':'success'},
                      {'name':'Real pf integration (disposable VM)','conclusion':'success'}]}
        def responses(first, second):
            return mock.patch.object(gu,'run',side_effect=[json.dumps({'workflow_runs':[first]}),json.dumps(second)])
        with responses(run,jobs):self.assertEqual(gu.ci_passed(sha,'/fake/gh'),run['html_url'])
        for field,value in (('head_sha','b'*40),('head_branch','other'),('event','pull_request'),
                            ('conclusion','failure'),('status','in_progress')):
            bad=dict(run);bad[field]=value
            with responses(bad,jobs),self.assertRaises(RuntimeError):gu.ci_passed(sha,'/fake/gh')
        bad=copy.deepcopy(jobs);bad['jobs'][1]['conclusion']='failure'
        with responses(run,bad),self.assertRaises(RuntimeError):gu.ci_passed(sha,'/fake/gh')

    def test_hook_retains_automatic_and_manual_safe_entry_points(self):
        source='''class Example {
    /// Runs the root CLI through the macOS administrator prompt.
    func admin() { }
    func applicationDidFinishLaunching(_ notification: Notification) {
    }
    func update() { unsafePullAndReinstall() }
    func uninstall() { }
}'''
        patched=gu.inject_hook(source)
        self.assertIn('netguardSafeGUIUpdate()',patched)
        self.assertIn('manual: true',patched)
        self.assertNotIn('unsafePullAndReinstall',patched)
        self.assertEqual(gu.inject_hook(patched),patched)
        with self.assertRaises(RuntimeError):gu.inject_hook('unrecognized UI')


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=pathlib.Path(self.tmp.name)
        self.root=self.base/'root';(self.root/'lib').mkdir(parents=True);(self.root/'bin').mkdir()
        self.app=self.base/'NetGuard.app';(self.app/'Contents/MacOS').mkdir(parents=True)
        (self.app/'Contents/MacOS/NetGuard').write_bytes(b'old gui')
        (self.app/'Contents/Info.plist').write_bytes(b'unchanged plist')
        self.cache=self.base/'cache';self.stage=self.cache/'candidate-safe';self.stage.mkdir(parents=True)
        (self.stage/'NetGuard').write_bytes(b'new gui')
        (self.stage/'Info.plist').write_bytes(b'unchanged plist')
        for n in ('config.json','python-path','source.json'):(self.root/n).write_text('fixed '+n)
        self.policy={'base_commit':'a'*40,'gui_commit':'a'*40,'repo':'/fake/repo','core_manifest':{'fixed':'hash'}}
        gu.atomic_json(self.root/'gui-update-policy.json',self.policy)
        gu.atomic_json(self.root/'status.json',safe_status())
        gu.atomic_json(self.stage/'candidate.json',{'commit':'b'*40,'binary_sha256':gu.digest(self.stage/'NetGuard'),
                                                  'plist_sha256':gu.digest(self.stage/'Info.plist')})
        account=pwd.getpwuid(os.getuid())
        self.calls=[]
        def runner(argv,**kw):
            args=[str(a) for a in argv];self.calls.append(args)
            return ''
        for patch in (mock.patch.object(gu,'ROOT',self.root),mock.patch.object(gu,'APP',self.app),
                      mock.patch.object(gu.os,'geteuid',return_value=0),
                      mock.patch.object(gu,'user_paths',return_value=(account,self.cache)),
                      mock.patch.object(gu,'installed_manifest',return_value={'fixed':'hash'}),
                      mock.patch.object(gu,'ci_passed',return_value='https://example.test/ci'),
                      mock.patch.object(gu,'gh_path',return_value='/fake/gh'),
                      mock.patch.object(gu,'healthy',return_value=True),mock.patch.object(gu,'run',side_effect=runner)):
            patch.start();self.addCleanup(patch.stop)

    def test_only_gui_changes_and_only_gui_process_restarts(self):
        originals={n:(self.root/n).read_bytes() for n in ('config.json','python-path','source.json')}
        result=gu.apply(self.stage.name)
        self.assertEqual(result['status'],'installed')
        self.assertEqual((self.app/'Contents/MacOS/NetGuard').read_bytes(),b'new gui')
        for n,content in originals.items():self.assertEqual((self.root/n).read_bytes(),content)
        actions=[' '.join(c) for c in self.calls]
        self.assertTrue(any(c.endswith('/bin/netguard verify') for c in actions))
        self.assertTrue(any('com.netguard.menu' in c for c in actions))
        self.assertFalse(any('pfctl' in c or 'com.netguard.daemon' in c or 'install.sh' in c for c in actions))

    def test_verify_failure_leaves_installed_gui_unchanged(self):
        def runner(argv,**kw):
            if str(argv[0]).endswith('/bin/netguard'):raise RuntimeError('verify failed')
            return ''
        with mock.patch.object(gu,'run',side_effect=runner),self.assertRaises(RuntimeError):gu.apply(self.stage.name)
        self.assertEqual((self.app/'Contents/MacOS/NetGuard').read_bytes(),b'old gui')

    def test_core_changes_or_hash_changes_block_before_any_gui_replacement(self):
        with mock.patch.object(gu,'installed_manifest',return_value={'fixed':'changed'}),self.assertRaises(RuntimeError):
            gu.apply(self.stage.name)
        with mock.patch.object(gu,'run',return_value='macos/netguard/service.py\0'),self.assertRaises(RuntimeError):
            gu.apply(self.stage.name)
        self.assertEqual((self.app/'Contents/MacOS/NetGuard').read_bytes(),b'old gui')

    def test_changed_candidate_or_app_identity_is_refused(self):
        (self.stage/'NetGuard').write_bytes(b'tampered')
        with self.assertRaises(RuntimeError):gu.apply(self.stage.name)
        (self.stage/'NetGuard').write_bytes(b'new gui')
        (self.app/'Contents/Info.plist').write_bytes(b'other app identity')
        with self.assertRaises(RuntimeError):gu.apply(self.stage.name)
        self.assertEqual((self.app/'Contents/MacOS/NetGuard').read_bytes(),b'old gui')

    def test_symlink_and_traversal_are_rejected(self):
        with self.assertRaises(RuntimeError):gu.apply('../outside')
        link=self.cache/'candidate-link';link.symlink_to(self.stage,target_is_directory=True)
        with self.assertRaises(RuntimeError):gu.apply(link.name)
        (self.stage/'NetGuard').unlink();(self.stage/'NetGuard').symlink_to(self.app/'Contents/MacOS/NetGuard')
        with self.assertRaises(RuntimeError):gu.apply(self.stage.name)

    def test_signing_failure_rolls_back_gui(self):
        def runner(argv,**kw):
            if str(argv[0])=='/usr/bin/codesign' and (self.app/'Contents/MacOS/NetGuard').read_bytes()==b'new gui':
                raise RuntimeError('signing failure')
            return ''
        with mock.patch.object(gu,'run',side_effect=runner),self.assertRaises(RuntimeError):gu.apply(self.stage.name)
        self.assertEqual((self.app/'Contents/MacOS/NetGuard').read_bytes(),b'old gui')


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)/'root';self.root.mkdir()
        self.cache=pathlib.Path(self.tmp.name)/'cache'
        self.policy={'repo':'/fake/repo','base_commit':'a'*40,'gui_commit':'a'*40,'core_manifest':{}}
        gu.atomic_json(self.root/'gui-update-policy.json',self.policy)
        gu.atomic_json(self.root/'status.json',safe_status())
        self.sha='a'*40;self.changed='';self.calls=[]
        account=pwd.getpwuid(os.getuid())
        def runner(argv,**kw):
            args=[str(a) for a in argv];self.calls.append(args)
            if 'get-url' in args:return 'https://github.com/fenghualu-bb/netguard.git\n'
            if 'rev-parse' in args:return self.sha if args[-1].startswith('refs/') else 'a'*40
            if 'diff' in args:return self.changed
            if 'show' in args and args[-1].endswith('.swift'):
                return 'class A {\n    /// Runs the root CLI through the macOS administrator prompt.\n    func admin() { }\n    func applicationDidFinishLaunching(_ notification: Notification) { }\n    func update() { }\n    func uninstall() { }\n}'
            if 'show' in args:return '<?xml version="1.0"?><plist version="1.0"><dict/></plist>'
            if 'swiftc' in args:pathlib.Path(args[args.index('-o')+1]).write_bytes(b'compiled GUI')
            return ''
        for patch in (mock.patch.object(gu,'ROOT',self.root),mock.patch.object(gu.os,'geteuid',return_value=501),
                      mock.patch.object(gu,'user_paths',return_value=(account,self.cache)),
                      mock.patch.object(gu,'require_manifest'),mock.patch.object(gu,'healthy',return_value=True),
                      mock.patch.object(gu,'ci_passed',return_value='https://example.test/ci'),
                      mock.patch.object(gu,'gh_path',return_value='/fake/gh'),
                      mock.patch.object(gu,'run',side_effect=runner)):
            patch.start();self.addCleanup(patch.stop)

    def test_no_new_commit_does_not_build_install_or_modify_working_tree(self):
        self.assertEqual(gu.prepare()['status'],'current')
        self.assertFalse(self.cache.exists())
        self.assertFalse(any('pull' in c or 'checkout' in c or 'reset' in c or 'swiftc' in c for c in self.calls))

    def test_protection_update_is_queued_without_running_it(self):
        self.sha='b'*40;self.changed='macos/netguard/probes.py\0'
        self.assertEqual(gu.prepare()['status'],'blocked')
        self.assertFalse(self.cache.exists())
        self.assertFalse(any('swiftc' in c for c in self.calls))

    def test_gui_update_is_built_in_private_stage_without_executing_installer(self):
        self.sha='b'*40;self.changed='macos/app/NetGuardApp.swift\0'
        result=gu.prepare()
        self.assertEqual(result['status'],'ready')
        staged=self.cache/result['stage']
        self.assertEqual((staged/'NetGuard').read_bytes(),b'compiled GUI')
        self.assertIn('netguardSafeGUIUpdate()', (staged/'NetGuardApp.swift').read_text())
        self.assertFalse(any('install.sh' in c or 'pfctl' in c or 'pull' in c for c in self.calls))

    def test_ci_transport_failure_keeps_installed_version(self):
        self.sha='b'*40;self.changed='macos/app/NetGuardApp.swift\0'
        with mock.patch.object(gu,'ci_passed',side_effect=RuntimeError('network EOF')),self.assertRaises(RuntimeError):
            gu.prepare()
        self.assertFalse(self.cache.exists())
