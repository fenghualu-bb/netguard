import copy
import importlib.machinery
import importlib.util
from pathlib import Path
import time
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('netguard_workbench', str(ROOT / 'workbench.pyw'))
spec = importlib.util.spec_from_loader(loader.name, loader)
wb = importlib.util.module_from_spec(spec)
loader.exec_module(wb)


def snapshot():
    return {
        'time': '12:00:00', 'collected_at': time.time(),
        'whitelist': ['203.0.113.10'], 'egress': '203.0.113.10',
        'egress_claude': '203.0.113.10', 'realip': False,
        'guard': {'state': 'allowed', 'ip': '203.0.113.10', 'daemon_running': True,
                  'network': {'ready': True, 'updated_at': time.time(), 'applied_state': 'allowed'}},
        'guard_protection_enabled': True, 'guard_network_enabled': True,
        'claude_expected': r'C:\Claude\claude.exe', 'claude_configured': r'C:\Claude\claude.exe',
        'claude_path_exists': True, 'cli_path_exists': True,
        'flclash_ui': True, 'flclash_core': True, 'tun_up': True,
        'flclash_mode': 'global', 'strict_route': True, 'fl_config_note': '',
        'ng_installed': True, 'ng_outdated': False,
        'ng_status': {'updated_at': time.time(), 'wanted_killswitch': True,
                      'active_killswitch': True, 'wanted_claude_block': False,
                      'active_claude_block': False, 'filter_count': 14, 'error': None,
                      'status_version': 2, 'killswitch_complete': True,
                      'claude_block_complete': True, 'expected_filter_count': 14,
                      'integrity_ok': True,
                      'strict_route_runtime': {'checked_at': time.time(), 'detected': True, 'dns_block': 2,
                                               'total': 5, 'names': [], 'error': None},
                      'guard': {'enabled': True, 'lockdown': False, 'since': 0, 'reasons': [], 'bad_streak': 0,
                                'confirm': 2, 'interval': 10, 'last_check': time.time(), 'last_findings': [], 'triggers': 0}},
        'prefs_strict': True,
        'ng_log': '', 'health_task': '0|12:10:00', 'health_last': '2026-10-29 12:00:00 OK',
        'health_task_enabled': True, 'health_last_run': time.time(),
        'health_next_run': time.time()+600, 'health_log_updated_at': time.time(),
        'isolation_targets_ok': True,
        'ui_source_changed': False,
        'guard_patch_ok': True,
    }


class WidgetSink:
    def __init__(self): self.values = {}
    def config(self, **values): self.values.update(values)
    configure = config


class ViewSink:
    def __init__(self):
        self.values = {}
        self.verdict = WidgetSink()
        self.updated = WidgetSink()
        self.btn_install = WidgetSink()
        self.btn_kill = WidgetSink()
        self.btn_realip = WidgetSink()
        self.btn_release = WidgetSink()
        self.busy = False
        self.action_buttons = []
    def set(self, key, text, color=None): self.values[key] = (text, color)
    def sync_buttons(self): pass


class VerdictTests(unittest.TestCase):
    def test_locked_manifest_scope_does_not_claim_new_version_is_isolated(self):
        def change(s):
            s['ng_status'].update(wanted_claude_block=True, active_claude_block=True, claude_block_complete=True)
            s['ng_status']['guard'].update(lockdown=True, last_findings=['current Store path is not covered'])
        view = self.render(change)
        self.assertIn('清单内程序', view.values['ag_state'][0])
        self.assertIn('仍有异常', view.verdict.values['text'])
        self.assertNotIn('检查已通过', view.verdict.values['text'])

    def test_partial_isolation_does_not_claim_claude_already_isolated(self):
        def change(s):
            s['ng_status'].update(active_killswitch=True, killswitch_complete=True,
                                  wanted_claude_block=True, active_claude_block=False,
                                  claude_block_complete=False, integrity_ok=False,
                                  filter_count=16, expected_filter_count=32,
                                  base_filter_count=14, expected_base_filter_count=14,
                                  required_claude_filter_count=18, covered_claude_filter_count=2)
            s['ng_status']['guard'].update(lockdown=True,reasons=['old desktop path'],last_findings=['isolation incomplete'])
        view=self.render(change)
        self.assertEqual(view.values['ng_state'][1],wb.GOOD)
        self.assertIn('2/18',view.values['ng_claude'][0])
        self.assertNotIn('已隔离',view.values['ag_state'][0])
        self.assertIn('当前',view.values['ag_reason'][0])
        self.assertEqual(view.verdict.values['foreground'],wb.BAD)

    def render(self, change=None):
        s = snapshot()
        if change: change(s)
        view = ViewSink()
        wb.Workbench.show(view, s)
        return view

    def assert_not_green(self, change):
        view = self.render(change)
        self.assertNotEqual(view.verdict.values.get('foreground'), wb.GOOD)

    def test_verified_snapshot_is_green(self):
        self.assertEqual(self.render().verdict.values['foreground'], wb.GOOD)

    def test_unknown_strict_route_cannot_be_green(self):
        # 没有运行时证据时，配置未知不能算绿（有新鲜运行时证据时以运行时为准，见 StrictRouteEvidenceTests）
        self.assert_not_green(lambda s: (s.update(strict_route=None), s['ng_status'].pop('strict_route_runtime')))

    def test_direct_mode_cannot_be_green(self):
        self.assert_not_green(lambda s: s.update(flclash_mode='direct'))

    def test_missing_desktop_discovery_cannot_claim_matching_path(self):
        view = self.render(lambda s: s.update(claude_expected=None))
        self.assertNotEqual(view.values['guard_path'][1], wb.GOOD)

    def test_blocked_guard_cannot_be_green(self):
        self.assert_not_green(lambda s: s['guard'].update(state='blocked'))

    def test_stale_helper_cannot_be_green(self):
        self.assert_not_green(lambda s: s['guard']['network'].update(updated_at=time.time()-300))

    def test_disabled_guard_protection_cannot_be_green(self):
        self.assert_not_green(lambda s: s.update(guard_protection_enabled=False))

    def test_wfp_enumeration_error_cannot_be_green(self):
        self.assert_not_green(lambda s: s['ng_status'].update(error='access denied'))

    def test_missing_wfp_filter_cannot_be_green(self):
        self.assert_not_green(lambda s: s['ng_status'].update(filter_count=13))

    def test_future_status_timestamp_is_not_fresh(self):
        self.assert_not_green(lambda s: s['ng_status'].update(updated_at=time.time()+600))

    def test_claude_isolation_mismatch_cannot_be_green(self):
        self.assert_not_green(lambda s: s['ng_status'].update(wanted_claude_block=True))

    def test_real_ip_marker_without_isolation_is_red(self):
        view = self.render(lambda s: s.update(realip=True))
        self.assertEqual(view.verdict.values['foreground'], wb.BAD)

    def test_changed_running_ui_source_cannot_be_green(self):
        self.assert_not_green(lambda s: s.update(ui_source_changed=True))

    def test_legacy_status_does_not_claim_integrity_verified(self):
        def change(s):
            for key in ('status_version', 'killswitch_complete', 'claude_block_complete', 'integrity_ok', 'expected_filter_count'):
                s['ng_status'].pop(key)
        self.assert_not_green(change)

    def test_disabled_health_schedule_cannot_be_green(self):
        self.assert_not_green(lambda s: s.update(health_task_enabled=False))

    def test_old_successful_health_log_cannot_be_green(self):
        self.assert_not_green(lambda s: s.update(health_log_updated_at=time.time()-86400))

    def test_missing_next_health_run_cannot_be_green(self):
        self.assert_not_green(lambda s: s.update(health_next_run=0))


class GuardViewTests(unittest.TestCase):
    def render(self, change):
        s=snapshot(); change(s); view=ViewSink(); wb.Workbench.show(view,s); return view
    def g(self, s, **kw): s['ng_status']['guard'].update(kw)

    def test_standby_guard_is_green(self):
        view=self.render(lambda s: None)
        self.assertEqual(view.values['ag_state'][1],wb.GOOD)
        self.assertEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_lockdown_is_red_and_first_in_verdict(self):
        view=self.render(lambda s: (self.g(s,lockdown=True,since=time.time(),reasons=['普通出口 1.2.3.4 不在白名单'],triggers=1),
                                    s['ng_status'].update(active_claude_block=True,wanted_claude_block=True)))
        self.assertEqual(view.verdict.values['foreground'],wb.BAD)
        self.assertIn('自动防护已触发',view.verdict.values['text'])
        self.assertIn('1.2.3.4',view.values['ag_reason'][0])
        self.assertIn('自动防护锁定',view.values['ng_claude'][0])

    def test_lockdown_is_not_mistaken_for_real_ip_mode(self):
        s=snapshot(); self.g(s,lockdown=True); s['ng_status'].update(active_claude_block=True)
        st=s['ng_status']; lockdown=bool((st.get('guard') or {}).get('lockdown'))
        self.assertFalse(bool(st.get('active_claude_block')) and not lockdown)

    def test_disabled_guard_is_not_green(self):
        view=self.render(lambda s: self.g(s,enabled=False))
        self.assertNotEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_stale_guard_check_is_red(self):
        view=self.render(lambda s: self.g(s,last_check=time.time()-600))
        self.assertEqual(view.verdict.values['foreground'],wb.BAD)

    def test_old_admin_without_guard_is_pending(self):
        view=self.render(lambda s: s['ng_status'].pop('guard'))
        self.assertNotEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_confirming_streak_shown_as_warning(self):
        view=self.render(lambda s: self.g(s,bad_streak=1,last_findings=['TUN 虚拟网卡未连接']))
        self.assertEqual(view.values['ag_state'][1],wb.WARN)


class EventsTests(unittest.TestCase):
    def test_read_events_skips_garbage_and_limits(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'events.jsonl'
            lines=[wb.json.dumps({'ts':i,'type':'suspect','summary':str(i)}) for i in range(30)]+['not json','{"no_ts":1}']
            p.write_text('﻿'+'\n'.join(lines),encoding='utf-8')
            with patch.object(wb,'NETGUARD',Path(d)), patch.object(wb,'GUARD_EVENTS',Path(d)/'none.jsonl'):
                ev=wb.read_events(limit=10)
        self.assertTrue(all('ts' in e for e in ev))
        self.assertLessEqual(len(ev),10)
        self.assertEqual(ev[-1]['summary'],'29')

    def test_missing_events_file_is_empty(self):
        with tempfile.TemporaryDirectory() as d, patch.object(wb,'NETGUARD',Path(d)), patch.object(wb,'GUARD_EVENTS',Path(d)/'none.jsonl'):
            self.assertEqual(wb.read_events(),[])

    def test_both_sources_merged_in_time_order_with_source(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'events.jsonl').write_text(wb.json.dumps({'ts':10,'type':'trigger','summary':'ng'})+'\n',encoding='utf-8')
            (Path(d)/'cg.jsonl').write_text(wb.json.dumps({'ts':5,'type':'kill','summary':'cg','source':'ClaudeGuard'})+'\n',encoding='utf-8')
            with patch.object(wb,'NETGUARD',Path(d)), patch.object(wb,'GUARD_EVENTS',Path(d)/'cg.jsonl'):
                ev=wb.read_events()
        self.assertEqual([e['summary'] for e in ev],['cg','ng'])
        self.assertEqual([e['source'] for e in ev],['ClaudeGuard','NetGuard'])

    def test_severity_from_field_or_highest_reason(self):
        self.assertEqual(wb.event_severity({'severity':'中'}),'中')
        self.assertEqual(wb.event_severity({'reasons':[{'level':'低'},{'level':'高'}]}),'高')
        self.assertEqual(wb.event_severity({'reasons':['旧格式文字']}),'—')

    def test_reason_lines_show_level_and_explanation(self):
        lines=wb.reason_lines({'reasons':[{'text':'出口 9.9.9.9 不在白名单','level':'高','why':'账号有风控风险'}]})
        self.assertIn('【高】出口 9.9.9.9 不在白名单',lines[0])
        self.assertIn('危险说明：账号有风控风险',lines[0])


class GuardPatchTests(unittest.TestCase):
    def test_lost_claudeguard_patch_is_warned(self):
        s=snapshot(); s['guard_patch_ok']=False; v=ViewSink(); wb.Workbench.show(v,s)
        self.assertNotEqual(v.verdict.values['foreground'],wb.GOOD)
        self.assertIn('补丁丢失',v.verdict.values['text'])


class HealthTimingTests(unittest.TestCase):
    def render(self, change):
        s=snapshot(); change(s); view=ViewSink(); wb.Workbench.show(view,s); return view

    def test_task_running_right_now_is_still_green(self):
        # 2026-10-29 实测：采集恰逢任务运行，NextRunTime 比现在早几秒
        view=self.render(lambda s: s.update(health_next_run=time.time()-7))
        self.assertEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_next_run_long_past_is_not_green(self):
        view=self.render(lambda s: s.update(health_next_run=time.time()-600))
        self.assertNotEqual(view.verdict.values['foreground'],wb.GOOD)


class RefreshRecoveryTests(unittest.TestCase):
    def test_collection_exception_releases_refresh_and_retry_succeeds(self):
        with patch.object(wb, 'collect', side_effect=RuntimeError('injected collection error')):
            app = wb.Workbench()
            app.withdraw()
            try:
                end = time.monotonic()+1.5
                while time.monotonic() < end:
                    app.update()
                    time.sleep(.01)
                self.assertFalse(app._refreshing, 'collector exception left the UI stuck refreshing')
                self.assertEqual(str(app.verdict.cget('foreground')), wb.BAD)
                with patch.object(wb, 'collect', return_value=copy.deepcopy(snapshot())):
                    app.refresh()
                    end = time.monotonic()+1.5
                    while app._refreshing and time.monotonic() < end:
                        app.update()
                        time.sleep(.01)
                self.assertFalse(app._refreshing)
                self.assertEqual(str(app.verdict.cget('foreground')), wb.GOOD)
            finally:
                app.destroy()


class IsolationTests(unittest.TestCase):
    def test_disabled_killswitch_never_invites_switching_proxy(self):
        app = types.SimpleNamespace(busy=False)
        app.elevated = lambda action, done: done(0)
        wizard = types.SimpleNamespace(app=app, messages=[])
        wizard.say = lambda text, color=None: wizard.messages.append((text, color))
        status = snapshot()['ng_status']
        status['active_killswitch'] = False
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(wb, 'REALIP_FLAG', Path(directory)/'mode.json'), patch.object(wb.messagebox, 'askyesno', return_value=True), patch.object(wb, 'read_json', side_effect=lambda path: status if Path(path).name == 'status.json' else {}), patch.object(wb.psutil, 'process_iter', return_value=[]):
                wb.RealIpWizard.isolate(wizard)
        self.assertEqual(wizard.messages[-1][1], wb.BAD)

    def test_missing_manifest_target_prevents_isolation_instructions(self):
        app=types.SimpleNamespace(busy=False,state_data=snapshot())
        app.state_data['isolation_targets_ok']=False
        app.elevated=lambda action,done: done(0)
        wizard=types.SimpleNamespace(app=app,messages=[])
        wizard.say=lambda text,color=None: wizard.messages.append((text,color))
        status=snapshot()['ng_status']
        status['active_claude_block']=True
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(wb,'REALIP_FLAG',Path(directory)/'mode.json'),patch.object(wb.messagebox,'askyesno',return_value=True),patch.object(wb,'read_json',side_effect=lambda path: status if Path(path).name=='status.json' else {}),patch.object(wb.psutil,'process_iter',return_value=[]):
                wb.RealIpWizard.isolate(wizard)
        self.assertEqual(wizard.messages[-1][1],wb.BAD)

    def test_cached_coverage_does_not_override_current_missing_target(self):
        app=types.SimpleNamespace(busy=False,state_data=snapshot(),elevated=lambda action,done: done(0))
        wizard=types.SimpleNamespace(app=app,messages=[])
        wizard.say=lambda text,color=None: wizard.messages.append((text,color))
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(wb,'REALIP_FLAG',Path(directory)/'mode.json'),patch.object(wb.messagebox,'askyesno',return_value=True),patch.object(wb,'read_json',return_value=snapshot()['ng_status']),patch.object(wb,'isolation_targets_covered',return_value=False,create=True),patch.object(wb.psutil,'process_iter',return_value=[]):
                wb.RealIpWizard.isolate(wizard)
        self.assertEqual(wizard.messages[-1][1],wb.BAD)

    def test_post_uac_missing_isolation_never_reports_success(self):
        app=types.SimpleNamespace(busy=False,state_data=snapshot(),elevated=lambda action,done: done(0))
        wizard=types.SimpleNamespace(app=app,messages=[])
        wizard.say=lambda text,color=None: wizard.messages.append((text,color))
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(wb,'REALIP_FLAG',Path(directory)/'mode.json'),patch.object(wb.messagebox,'askyesno',return_value=True),patch.object(wb,'read_json',return_value=snapshot()['ng_status']),patch.object(wb,'isolation_targets_covered',return_value=True,create=True),patch.object(wb.psutil,'process_iter',return_value=[]):
                wb.RealIpWizard.isolate(wizard)
        self.assertEqual(wizard.messages[-1][1],wb.BAD)

    def test_post_uac_changed_target_coverage_never_reports_success(self):
        pre=snapshot()['ng_status']
        post=dict(pre,active_claude_block=True,wanted_claude_block=True)
        app=types.SimpleNamespace(busy=False,state_data=snapshot(),elevated=lambda action,done: done(0))
        wizard=types.SimpleNamespace(app=app,messages=[])
        wizard.say=lambda text,color=None: wizard.messages.append((text,color))
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(wb,'REALIP_FLAG',Path(directory)/'mode.json'),patch.object(wb.messagebox,'askyesno',return_value=True),patch.object(wb,'read_json',side_effect=lambda path: pre if not wizard.messages else post),patch.object(wb,'isolation_targets_covered',side_effect=[True,False],create=True),patch.object(wb.psutil,'process_iter',return_value=[]):
                wb.RealIpWizard.isolate(wizard)
        self.assertEqual(wizard.messages[-1][1],wb.BAD)


class ConfigEvidenceTests(unittest.TestCase):
    def test_empty_runtime_configuration_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.yaml'
            path.write_text('',encoding='utf-8')
            with patch.object(wb,'FLCLASH_CONFIG',path): result=wb.flclash_config()
        self.assertIsNone(result['strict_route'])
        self.assertEqual(result['flclash_mode'],'?')

    def test_explicit_false_is_distinct_from_missing_strict_route(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.yaml'
            path.write_text('mode: global\ntun:\n  strict-route: false\n',encoding='utf-8')
            with patch.object(wb,'FLCLASH_CONFIG',path): result=wb.flclash_config()
        self.assertIs(result['strict_route'],False)

    def test_strict_route_outside_tun_does_not_verify_tun(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.yaml'
            path.write_text('mode: global\nother:\n  strict-route: true\n',encoding='utf-8')
            with patch.object(wb,'FLCLASH_CONFIG',path): result=wb.flclash_config()
        self.assertIsNone(result['strict_route'])

    def test_config_metadata_and_prefs_are_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'config.yaml'
            path.write_text('mode: global\ntun:\n  strict-route: true\n',encoding='utf-8')
            prefs={'flutter.config': wb.json.dumps({'patchClashConfig': {'tun-override-keys': ['strict-route'], 'tun-override': {'strict-route': True}}})}
            (Path(directory)/'shared_preferences.json').write_text(wb.json.dumps(prefs),encoding='utf-8')
            result=wb.flclash_config(path,'测试')
            size=path.stat().st_size
        self.assertIs(result['strict_route'],True)
        self.assertIs(result['prefs_strict'],True)
        self.assertEqual(result['fl_config_size'],size)
        self.assertEqual(result['fl_config_source'],'测试')

    def test_prefs_without_override_key_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            prefs={'flutter.config': wb.json.dumps({'patchClashConfig': {'tun-override-keys': [], 'tun-override': {'strict-route': False}}})}
            (Path(directory)/'shared_preferences.json').write_text(wb.json.dumps(prefs),encoding='utf-8')
            self.assertIsNone(wb.prefs_strict_route(directory))

    def test_locator_prefers_running_flclash_environment(self):
        class Proc:
            info={'name':'FlClash.exe'}
            def environ(self): return {'APPDATA': r'C:\Users\real\AppData\Roaming'}
        with patch.object(wb.psutil,'process_iter',return_value=[Proc()]):
            path,source=wb.locate_flclash_config()
        self.assertEqual(path,Path(r'C:\Users\real\AppData\Roaming')/'com.follow'/'clash'/'config.yaml')
        self.assertEqual(source,'FlClash 进程')

    def test_locator_falls_back_when_flclash_not_running(self):
        with patch.object(wb.psutil,'process_iter',return_value=[]):
            path,source=wb.locate_flclash_config()
        self.assertEqual(path,wb.FLCLASH_CONFIG)
        self.assertIn('未运行',source)


class StrictRouteEvidenceTests(unittest.TestCase):
    def render(self, change):
        s=snapshot(); change(s); view=ViewSink(); wb.Workbench.show(view,s); return view

    def rt(self, s, **kw): s['ng_status']['strict_route_runtime'].update(kw)

    def test_runtime_detected_is_green(self):
        view=self.render(lambda s: None)
        self.assertEqual(view.values['fl_strict'][1],wb.GOOD)
        self.assertEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_runtime_proof_overrides_misread_empty_config(self):
        # 复现 2026-10-29 Codex 误判：读到错误目录的 0 字节文件，但内核规则确实在执行
        def misread(s): s.update(strict_route=None, flclash_mode='global', prefs_strict=False)
        view=self.render(misread)
        self.assertEqual(view.values['fl_strict'][1],wb.GOOD)
        self.assertIn('以运行时为准',view.values['fl_strict'][0])

    def test_running_core_without_runtime_filters_is_not_effective(self):
        view=self.render(lambda s: self.rt(s,detected=False,dns_block=0,total=0))
        self.assertEqual(view.values['fl_strict'][1],wb.BAD)
        self.assertNotEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_stale_runtime_evidence_cannot_be_green(self):
        view=self.render(lambda s: self.rt(s,checked_at=time.time()-3600))
        self.assertNotEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_runtime_probe_error_cannot_be_green(self):
        view=self.render(lambda s: self.rt(s,error='WFP 0x5'))
        self.assertNotEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_old_admin_without_runtime_field_is_pending_not_green(self):
        view=self.render(lambda s: s['ng_status'].pop('strict_route_runtime'))
        self.assertIn('更新管理脚本',view.values['fl_strict'][0])
        self.assertNotEqual(view.verdict.values['foreground'],wb.GOOD)

    def test_core_not_running_cannot_claim_effective(self):
        view=self.render(lambda s: (self.rt(s,detected=False), s.update(flclash_core=False)))
        self.assertNotEqual(view.values['fl_strict'][1],wb.GOOD)


if __name__ == '__main__': unittest.main()
