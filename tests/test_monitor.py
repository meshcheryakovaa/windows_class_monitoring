import contextlib
import ctypes
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import battery_monitor as monitor


class IsolatedTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {"BATTERY_MONITOR_DATA_DIR": self.temporary.name})
        self.environment.start()

    def tearDown(self):
        log = monitor.logging.getLogger("battery-monitor")
        for handler in log.handlers[:]:
            handler.close()
            log.removeHandler(handler)
        self.environment.stop()
        self.temporary.cleanup()


class ConfigTests(IsolatedTest):
    def test_identity_survives_settings_changes(self):
        first = monitor.load_config()
        with contextlib.redirect_stdout(io.StringIO()):
            monitor.main(["config", "set", "display-name", "Ноутбук №12"])
            monitor.main(["config", "set", "interval", "600"])
        second = monitor.load_config()
        self.assertEqual(first["device_id"], second["device_id"])
        self.assertEqual(second["display_name"], "Ноутбук №12")
        self.assertEqual(second["interval"], 600)

    def test_invalid_values_do_not_replace_config(self):
        original = monitor.load_config()
        for args in (["interval", "0"], ["interval", "abc"], ["disk-path", "disk:/private"],
                     ["disk-path", "app:/foo/../bar"], ["display-name", "a" * 101]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                monitor.main(["config", "set", *args])
            self.assertEqual(monitor.load_config(), original)

    def test_rejects_invalid_cloud_paths(self):
        for path in ("app:/", "app:/folder/", "app:/a//b", "app:/a/./b", "app:/a\\b", "app:/a\nb"):
            config = monitor.load_config()
            config["disk_path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                monitor.validate_config(config)

    def test_show_json_never_contains_token_data(self):
        monitor.write_json(monitor.data_dir() / "token.dat", {"dpapi": "not-a-real-secret"})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            monitor.main(["config", "show", "--json"])
        self.assertNotIn("not-a-real-secret", output.getvalue())
        self.assertTrue(json.loads(output.getvalue())["token_configured"])

    def test_atomic_write_leaves_valid_json_and_no_temporary_files(self):
        path = monitor.data_dir() / "sample.json"
        monitor.write_json(path, {"label": "Тюмень"})
        monitor.write_json(path, {"label": "Обновление"})
        self.assertEqual(monitor.read_json(path), {"label": "Обновление"})
        self.assertEqual(list(monitor.data_dir().glob("sample.json.*")), [])

    def test_corrupt_config_is_not_silently_reset(self):
        (monitor.data_dir() / "config.json").write_text("broken", encoding="utf-8")
        with self.assertRaises(ValueError):
            monitor.load_config()


class PowerTests(unittest.TestCase):
    def decode(self, percent=42, flags=0, ac=0, remaining=3600):
        status = monitor.PowerStatus()
        status.BatteryLifePercent = percent
        status.BatteryFlag = flags
        status.ACLineStatus = ac
        status.BatteryLifeTime = remaining
        return monitor.decode_power(status)

    def test_charging_and_power_are_separate(self):
        result = self.decode(percent=100, flags=1, ac=1)
        self.assertTrue(result["ac_connected"])
        self.assertFalse(result["charging"])
        self.assertIsNone(result["remaining_seconds"])
        self.assertTrue(self.decode(flags=8, ac=1)["charging"])

    def test_unknown_values_are_not_reported_as_zero_charge(self):
        result = self.decode(percent=255, flags=255, ac=255, remaining=0xFFFFFFFF)
        for key in ("battery_present", "battery_percent", "ac_connected", "charging", "remaining_seconds"):
            self.assertIsNone(result[key])

    def test_desktop_pc_has_no_battery_percentage(self):
        result = self.decode(percent=0, flags=128, ac=1)
        self.assertFalse(result["battery_present"])
        self.assertIsNone(result["battery_percent"])
        self.assertFalse(result["charging"])

    def test_zero_percent_is_valid(self):
        self.assertEqual(self.decode(percent=0)["battery_percent"], 0)


class DiskTests(unittest.TestCase):
    def test_oauth_only_sent_to_api_not_signed_upload_url(self):
        requests = []

        def response(request, timeout):
            requests.append(request)
            body = b'{"href":"https://upload.example/file?signature=private"}' if len(requests) == 1 else b''
            context = Mock()
            context.__enter__ = Mock(return_value=Mock(read=Mock(return_value=body)))
            context.__exit__ = Mock(return_value=False)
            return context

        config = {"disk_path": "app:/wcm/devices", "device_id": "different-device"}
        with patch.object(monitor, "urlopen", side_effect=response):
            monitor.DiskClient("test-secret").upload(config, {"battery_percent": 42})
        self.assertIn("different-device.json", requests[0].full_url)
        self.assertEqual(requests[0].get_header("Authorization"), "OAuth test-secret")
        self.assertIsNone(requests[1].get_header("Authorization"))
        self.assertEqual(requests[1].method, "PUT")
        self.assertEqual(json.loads(requests[1].data)["battery_percent"], 42)

    def test_errors_do_not_leak_signed_urls_or_token(self):
        error = HTTPError("https://example/?token=secret", 401, "secret", {}, None)
        with patch.object(monitor, "urlopen", side_effect=error), self.assertRaises(monitor.DiskError) as raised:
            monitor.DiskClient("secret").test()
        self.assertNotIn("secret", str(raised.exception))
        self.assertIn("401", str(raised.exception))

    def test_network_failure_is_actionable(self):
        with patch.object(monitor, "urlopen", side_effect=URLError("secret-url")), self.assertRaises(monitor.DiskError) as raised:
            monitor.DiskClient("secret").test()
        self.assertIn("интернет", str(raised.exception))
        self.assertNotIn("secret", str(raised.exception))

    def test_http_transfer_url_rejected(self):
        with self.assertRaises(monitor.DiskError):
            monitor.DiskClient("secret").request("PUT", "http://example/unsafe", b"{}", auth=False)

    def test_folder_conflict_is_only_accepted_for_directory(self):
        client = monitor.DiskClient("secret")
        client.request = Mock(side_effect=[monitor.DiskError("HTTP 409: conflict"), {"type": "file"}])
        with self.assertRaisesRegex(monitor.DiskError, "существует файл"):
            client.ensure_folder("app:/wcm")

    def test_folder_creation_does_not_hide_authorization_error(self):
        client = monitor.DiskClient("secret")
        client.request = Mock(side_effect=monitor.DiskError("HTTP 403: denied"))
        with self.assertRaises(monitor.DiskError):
            client.ensure_folder("app:/wcm/devices")
        self.assertEqual(client.request.call_count, 1)


class ProcessTests(IsolatedTest):
    def test_lock_excludes_second_process_and_is_released_on_exit(self):
        lock = monitor.InstanceLock()
        self.assertTrue(lock.acquire())
        try:
            result = subprocess.run([sys.executable, "-c", "import battery_monitor as m; print(m.is_running())"],
                                    cwd=monitor.ROOT, text=True, capture_output=True, check=True)
            self.assertEqual(result.stdout.strip(), "True")
        finally:
            lock.close()
        self.assertFalse(monitor.is_running())

    def test_stop_does_not_kill_unrelated_pid(self):
        monitor.write_json(monitor.data_dir() / "status.json", {"pid": os.getpid()})
        with contextlib.redirect_stdout(io.StringIO()):
            monitor.stop_agent()
        self.assertFalse((monitor.data_dir() / "stop.request").exists())

    def test_failed_manual_upload_preserves_last_success(self):
        previous = {"last_success_at": "2026-01-01T00:00:00Z"}
        monitor.write_json(monitor.data_dir() / "status.json", previous)
        with patch.object(monitor, "send_once", side_effect=monitor.DiskError("offline")):
            with self.assertRaises(monitor.DiskError):
                monitor.request_send()
        self.assertEqual(monitor.read_json(monitor.data_dir() / "status.json"), previous)


class AgentTests(IsolatedTest):
    def payload(self, config):
        return {"computer_name": "PC1", "battery_percent": 42, "ac_connected": False}

    def test_network_failure_keeps_last_success_and_waits_before_retry(self):
        monitor.load_config()
        monitor.write_json(monitor.data_dir() / "status.json", {"last_success_at": "previous-success"})
        clock = [0.0]

        def sleep(seconds):
            clock[0] += seconds
            if clock[0] >= 2:
                monitor.write_json(monitor.data_dir() / "stop.request", {})

        with patch.object(monitor, "require_windows"), patch.object(monitor, "send_once", side_effect=monitor.DiskError("offline")) as send, patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), patch.object(monitor.time, "sleep", side_effect=sleep):
            monitor.run_agent()
        self.assertEqual(send.call_count, 1)
        result = monitor.read_json(monitor.data_dir() / "status.json")
        self.assertEqual(result["last_success_at"], "previous-success")
        self.assertEqual(result["last_error"], "offline")
        self.assertFalse(monitor.is_running())

    def test_configuration_changes_are_applied_without_restart(self):
        config = monitor.load_config()
        ticks = [0]

        def sleep(seconds):
            ticks[0] += 1
            if ticks[0] == 1:
                monitor.write_json(monitor.data_dir() / "config.json", {**config, "interval": 600})
            else:
                monitor.write_json(monitor.data_dir() / "stop.request", {})

        with patch.object(monitor, "require_windows"), patch.object(monitor, "send_once", side_effect=self.payload) as send, patch.object(monitor.time, "sleep", side_effect=sleep):
            monitor.run_agent()
        self.assertEqual([call.args[0]["interval"] for call in send.call_args_list], [300, 600])
        self.assertEqual(monitor.load_config()["device_id"], config["device_id"])

    def test_resume_triggers_immediate_upload(self):
        monitor.load_config()
        clock, ticks = [0.0], [0]

        def sleep(seconds):
            ticks[0] += 1
            clock[0] += 100
            if ticks[0] == 2:
                monitor.write_json(monitor.data_dir() / "stop.request", {})

        with patch.object(monitor, "require_windows"), patch.object(monitor, "send_once", side_effect=self.payload) as send, patch.object(monitor.time, "monotonic", side_effect=lambda: clock[0]), patch.object(monitor.time, "sleep", side_effect=sleep):
            monitor.run_agent()
        self.assertEqual(send.call_count, 2)

    def test_autostart_task_is_allowed_to_run_on_battery(self):
        xml = []

        def run(args, **kwargs):
            if args[0] == "whoami.exe":
                return subprocess.CompletedProcess(args, 0, '"DOMAIN\\user","S-1-5-21-123"\n', '')
            xml.append(Path(args[args.index("/XML") + 1]).read_text(encoding="utf-16"))
            return subprocess.CompletedProcess(args, 0)

        with patch.object(monitor, "require_windows"), patch.object(monitor.subprocess, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            monitor.autostart("enable")
        self.assertIn('<DisallowStartIfOnBatteries>false', xml[0])
        self.assertIn('<StopIfGoingOnBatteries>false', xml[0])
        self.assertIn('<LogonType>InteractiveToken', xml[0])
        self.assertIn('<RunLevel>LeastPrivilege', xml[0])


class UpdateTests(unittest.TestCase):
    def test_dirty_checkout_is_rejected_before_stopping(self):
        with patch.object(monitor, "git", return_value=" M battery_monitor.py"), patch.object(monitor, "stop_agent") as stop:
            with self.assertRaisesRegex(RuntimeError, "локальные изменения"):
                monitor.update()
            stop.assert_not_called()

    def test_failed_candidate_checks_leave_agent_running(self):
        def git(*args):
            return {("status", "--porcelain"): "", ("rev-parse", "HEAD"): "old",
                    ("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"): "origin/main",
                    ("rev-parse", "origin/main"): "new"}.get(args, "")
        with patch.object(monitor, "git", side_effect=git), patch.object(monitor, "verify_checkout", side_effect=RuntimeError("bad code")), patch.object(monitor, "stop_agent") as stop:
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, "bad code"):
                monitor.update()
            stop.assert_not_called()


@unittest.skipUnless(sys.platform == "win32", "Windows native integration")
class WindowsIntegrationTests(IsolatedTest):
    def test_dpapi_roundtrip(self):
        monitor.save_token("test-token-for-local-dpapi-only")
        self.assertEqual(monitor.load_token(), "test-token-for-local-dpapi-only")
        self.assertNotIn("test-token", (monitor.data_dir() / "token.dat").read_text())

    def test_native_power_api_returns_valid_shape(self):
        self.assertEqual(ctypes.sizeof(monitor.PowerStatus), 12)
        result = monitor.battery_status()
        self.assertIn(result["battery_present"], (True, False, None))
        self.assertTrue(result["battery_percent"] is None or 0 <= result["battery_percent"] <= 100)


if __name__ == "__main__":
    unittest.main()
