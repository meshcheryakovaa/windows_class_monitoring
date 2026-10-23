"""Windows battery agent and CLI. Python 3.10+, no third-party dependencies."""
from __future__ import annotations

import argparse
import base64
import csv
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import getpass
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
import uuid
import webbrowser
from xml.sax.saxutils import escape

VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
DEFAULT_PATH = "app:/windows-class-monitoring/devices"
API = "https://cloud-api.yandex.net/v1/disk/resources"
CONFIG_KEYS = {"display-name": "display_name", "interval": "interval", "disk-path": "disk_path"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def data_dir():
    # Test and managed deployments can explicitly select their data directory.
    path = Path(os.environ.get("BATTERY_MONITOR_DATA_DIR") or
                (Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "WindowsClassMonitoring"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def write_json(path, value):
    """Atomic replacement; independent temporary names also work with concurrent readers."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
        # Short retries allow Windows readers/antivirus to release the old file.
        for attempt in range(10):
            try:
                os.replace(name, path)
                break
            except PermissionError:
                if attempt == 9:
                    raise
                time.sleep(0.05)
    finally:
        Path(name).unlink(missing_ok=True)


def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("Настройки должны быть JSON-объектом")
    uuid.UUID(config["device_id"])
    interval = config.get("interval")
    if isinstance(interval, bool) or not isinstance(interval, int) or not 30 <= interval <= 86400:
        raise ValueError("Интервал должен быть целым числом от 30 до 86400 секунд")
    name = config.get("display_name")
    if not isinstance(name, str) or len(name) > 100:
        raise ValueError("Название: строка длиной до 100 символов")
    path = config.get("disk_path", "")
    parts = path.removeprefix("app:/").split("/")
    if (not path.startswith("app:/") or len(path) > 300 or
            any(p in ("", ".", "..") or ":" in p or "\\" in p or
                any(ord(c) < 32 for c in p) for p in parts)):
        raise ValueError("Путь должен иметь вид app:/папка/devices, без .. и завершающего /")
    return config


def load_config():
    path = data_dir() / "config.json"
    config = read_json(path)
    if config is None:
        config = {"device_id": str(uuid.uuid4()), "display_name": "", "interval": 300,
                  "disk_path": DEFAULT_PATH}
        write_json(path, config)
    return validate_config(config)


def require_windows():
    if sys.platform != "win32":
        raise RuntimeError("Эта команда доступна только в Windows 10/11")


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def dpapi(data: bytes, decrypt=False):
    require_windows()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    source_buffer = ctypes.create_string_buffer(data)
    source = DataBlob(len(data), ctypes.cast(source_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    target = DataBlob()
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(DataBlob)]
    function.restype = wintypes.BOOL
    if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel.LocalFree(ctypes.cast(target.pbData, ctypes.c_void_p))


def save_token(token):
    token = token.strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError("Введите непустой OAuth-токен без пробелов")
    write_json(data_dir() / "token.dat", {"dpapi": base64.b64encode(dpapi(token.encode())).decode()})


def load_token():
    saved = read_json(data_dir() / "token.dat")
    if not saved:
        raise RuntimeError("Нет токена. Выполните .\\battery.ps1 auth")
    try:
        return dpapi(base64.b64decode(saved["dpapi"], validate=True), decrypt=True).decode()
    except (ValueError, KeyError, OSError) as exc:
        raise RuntimeError("Не удалось расшифровать токен. Выполните auth под текущим пользователем") from exc


class PowerStatus(ctypes.Structure):
    # BYTE in ctypes.wintypes was signed in older Python versions. The Windows
    # contract uses unsigned bytes and 32-bit DWORDs, including the 255 sentinels.
    _fields_ = [("ACLineStatus", ctypes.c_uint8), ("BatteryFlag", ctypes.c_uint8),
                ("BatteryLifePercent", ctypes.c_uint8), ("SystemStatusFlag", ctypes.c_uint8),
                ("BatteryLifeTime", ctypes.c_uint32), ("BatteryFullLifeTime", ctypes.c_uint32)]


def decode_power(status):
    flags = status.BatteryFlag
    present = None if flags == 255 else not bool(flags & 128)
    percent = int(status.BatteryLifePercent)
    return {
        "battery_present": present,
        "battery_percent": percent if present is not False and percent <= 100 else None,
        "ac_connected": {0: False, 1: True}.get(status.ACLineStatus),
        "charging": bool(flags & 8) if flags != 255 and present else (False if present is False else None),
        "remaining_seconds": (int(status.BatteryLifeTime) if present is not False and
                              status.ACLineStatus == 0 and status.BatteryLifeTime != 0xFFFFFFFF else None),
    }


def battery_status():
    require_windows()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemPowerStatus.argtypes = [ctypes.POINTER(PowerStatus)]
    kernel.GetSystemPowerStatus.restype = wintypes.BOOL
    status = PowerStatus()
    if not kernel.GetSystemPowerStatus(ctypes.byref(status)):
        raise ctypes.WinError(ctypes.get_last_error())
    return decode_power(status)


def snapshot(config):
    return {"schema": "windows-class-monitoring/v1", "device_id": config["device_id"],
            "computer_name": socket.gethostname(), "display_name": config["display_name"],
            "agent_version": VERSION, "os": platform.platform(), "measured_at": utc_now(),
            "interval_seconds": config["interval"], **battery_status()}


class DiskError(RuntimeError):
    pass


class DiskClient:
    def __init__(self, token):
        self.token = token

    def request(self, method, url, body=None, auth=True):
        if urlparse(url).scheme != "https":
            raise DiskError("Диск вернул небезопасную ссылку")
        headers = {"Accept": "application/json", "User-Agent": "WindowsClassMonitoring/" + VERSION}
        if auth:
            headers["Authorization"] = "OAuth " + self.token
        if body is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"
        try:
            with urlopen(Request(url, data=body, headers=headers, method=method), timeout=15) as response:
                content = response.read()
                return json.loads(content) if content else {}
        except HTTPError as exc:
            messages = {401: "Токен недействителен или истёк; выполните auth",
                        403: "Нет доступа: проверьте права токена на папку приложения",
                        404: "Папка не найдена", 409: "Конфликт ресурса",
                        429: "Слишком много запросов; повторим позже", 507: "На Диске нет места"}
            # Never include response bodies/URLs in logs: signed URLs may contain credentials.
            raise DiskError(f"Яндекс Диск HTTP {exc.code}: {messages.get(exc.code, 'ошибка сервера')}") from None
        except (URLError, TimeoutError, OSError):
            raise DiskError("Яндекс Диск недоступен: проверьте интернет; повторим позже") from None

    def ensure_folder(self, path):
        current = "app:"
        for part in path.removeprefix("app:/").split("/"):
            current += "/" + part
            try:
                self.request("PUT", API + "?" + urlencode({"path": current}))
            except DiskError as exc:
                if "HTTP 409:" not in str(exc):
                    raise
                # A conflicting file is not a directory: fail instead of hiding the error.
                resource = self.request("GET", API + "?" + urlencode({"path": current, "limit": 0}))
                if resource.get("type") != "dir":
                    raise DiskError("По пути папки уже существует файл")

    def test(self):
        return self.request("GET", API + "?" + urlencode({"path": "app:/", "limit": 0}))

    def upload(self, config, payload):
        path = config["disk_path"] + "/" + config["device_id"] + ".json"
        link = self.request("GET", API + "/upload?" + urlencode({"path": path, "overwrite": "true"}))
        href = link.get("href")
        if not href:
            raise DiskError("Диск не вернул ссылку загрузки")
        # Signed transfer URL already authorizes the PUT: do not send the OAuth header.
        self.request("PUT", href, json.dumps(payload, ensure_ascii=False).encode("utf-8"), auth=False)


class InstanceLock:
    """OS-owned byte lock: released on crash, never kills a recycled PID."""
    def __init__(self):
        self.stream = None

    def acquire(self):
        path = data_dir() / "agent.lock"
        self.stream = open(path, "a+b")
        self.stream.seek(0, 2)
        if self.stream.tell() == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            self.stream.close()
            self.stream = None
            return False

    def close(self):
        if self.stream:
            if sys.platform == "win32":
                import msvcrt
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            self.stream.close()
            self.stream = None


def is_running():
    lock = InstanceLock()
    acquired = lock.acquire()
    lock.close()
    return not acquired


def logger():
    log = logging.getLogger("battery-monitor")
    if not log.handlers:
        handler = RotatingFileHandler(data_dir() / "agent.log", maxBytes=1_000_000,
                                      backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log


def send_once(config):
    client = DiskClient(load_token())
    client.ensure_folder(config["disk_path"])
    payload = snapshot(config)
    client.upload(config, payload)
    return payload


def run_agent():
    require_windows()
    lock = InstanceLock()
    if not lock.acquire():
        return
    directory = data_dir()
    stop_path, send_path = directory / "stop.request", directory / "send.request"
    status = read_json(directory / "status.json", {})
    status.update({"pid": os.getpid(), "started_at": utc_now(), "agent_version": VERSION,
                   "last_error": None})
    log = logger()
    stop_path.unlink(missing_ok=True)
    write_json(directory / "status.json", status)
    log.info("Agent %s started", VERSION)
    previous_config = None
    next_send = 0.0
    previous_tick = time.monotonic()
    try:
        while not stop_path.exists():
            now = time.monotonic()
            if now - previous_tick > 15:  # Resume after suspend/hibernate.
                next_send = 0.0
            previous_tick = now
            request = read_json(send_path, {})
            request_id = request.get("id") if isinstance(request, dict) else None
            try:
                config = load_config()
                if config != previous_config:
                    next_send = 0.0
                    previous_config = config.copy()
                if request_id or now >= next_send:
                    status["last_attempt_at"] = utc_now()
                    try:
                        payload = send_once(config)
                        status.update({"last_success_at": utc_now(), "last_error": None,
                                       "last_payload": payload})
                        log.info("Uploaded: %s, battery=%s, AC=%s", payload["computer_name"],
                                 payload["battery_percent"], payload["ac_connected"])
                        delay = config["interval"]
                    except (RuntimeError, ValueError, OSError) as exc:
                        status["last_error"] = str(exc)
                        log.warning("Upload failed: %s", exc)
                        delay = min(60, config["interval"])
                    status["completed_request_id"] = request_id
                    write_json(directory / "status.json", status)
                    if request_id:
                        # Do not delete a newer CLI request that arrived during upload.
                        if read_json(send_path, {}).get("id") == request_id:
                            send_path.unlink(missing_ok=True)
                    next_send = time.monotonic() + delay
            except (RuntimeError, ValueError, OSError, KeyError) as exc:
                if status.get("last_error") != str(exc):
                    log.error("Configuration error: %s", exc)
                    status["last_error"] = str(exc)
                    write_json(directory / "status.json", status)
            # Network work can take >15 seconds; only a gap in the idle wait means resume.
            previous_tick = time.monotonic()
            time.sleep(1)
    finally:
        status["stopped_at"] = utc_now()
        write_json(directory / "status.json", status)
        log.info("Agent stopped")
        lock.close()


def start_agent():
    require_windows()
    if is_running():
        print("Агент уже работает")
        return
    load_config()
    load_token()  # Fail visibly rather than spawning a permanently unauthenticated process.
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    if not pythonw.is_file():
        raise RuntimeError("Не найден pythonw.exe. Установите обычный Python для Windows")
    with open(data_dir() / "bootstrap.log", "w", encoding="utf-8") as errors:
        subprocess.Popen([str(pythonw), str(ROOT / "battery_monitor.py"), "run"],
                         cwd=ROOT, stdin=subprocess.DEVNULL, stdout=errors, stderr=errors,
                         creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
    for _ in range(50):
        if is_running():
            print("Агент запущен в фоне")
            return
        time.sleep(0.1)
    raise RuntimeError("Агент не запустился. Проверьте bootstrap.log командой logs --bootstrap")


def stop_agent():
    if not is_running():
        print("Агент уже остановлен")
        return
    write_json(data_dir() / "stop.request", {"at": utc_now()})
    for _ in range(600):
        if not is_running():
            print("Агент остановлен")
            return
        time.sleep(0.1)
    raise RuntimeError("Агент завершает сетевой запрос. Повторите stop через минуту")


def request_send():
    if not is_running():
        payload = send_once(load_config())
        status = read_json(data_dir() / "status.json", {})
        status.update({"last_success_at": utc_now(), "last_attempt_at": utc_now(),
                       "last_error": None, "last_payload": payload})
        write_json(data_dir() / "status.json", status)
        print("Данные отправлены")
        return
    request_id = uuid.uuid4().hex
    write_json(data_dir() / "send.request", {"id": request_id})
    for _ in range(900):
        status = read_json(data_dir() / "status.json", {})
        if status.get("completed_request_id") == request_id:
            if status.get("last_error"):
                raise RuntimeError(status["last_error"])
            print("Данные отправлены")
            return
        if not is_running():
            raise RuntimeError("Агент остановился до отправки")
        time.sleep(0.1)
    raise RuntimeError("Время ожидания истекло. Посмотрите status и logs")


def python_console():
    executable = Path(sys.executable)
    return executable.with_name("python.exe") if executable.name.lower() == "pythonw.exe" else executable


def task_name():
    return "WindowsClassMonitoring-" + hashlib.sha256(str(data_dir()).lower().encode()).hexdigest()[:12]


def autostart(action):
    require_windows()
    name = task_name()
    if action == "status":
        result = subprocess.run(["schtasks.exe", "/Query", "/TN", name], capture_output=True)
        print("Автозапуск включён" if result.returncode == 0 else "Автозапуск не зарегистрирован")
        return
    if action == "disable":
        if subprocess.run(["schtasks.exe", "/Query", "/TN", name], capture_output=True).returncode == 0:
            subprocess.run(["schtasks.exe", "/Delete", "/TN", name, "/F"], check=True)
        print("Автозапуск отключён; работающий агент остановите командой stop")
        return
    who = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"], capture_output=True,
                         text=True, check=True)
    sid = list(csv.reader(who.stdout.strip().splitlines()))[0][-1]
    executable = Path(sys.executable).with_name("pythonw.exe")
    args = subprocess.list2cmdline([str(ROOT / "battery_monitor.py"), "run"])
    xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <RegistrationInfo><Description>Battery telemetry to Yandex Disk</Description></RegistrationInfo>
 <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(sid)}</UserId></LogonTrigger></Triggers>
 <Principals><Principal id="Owner"><UserId>{escape(sid)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
 <Actions Context="Owner"><Exec><Command>{escape(str(executable))}</Command><Arguments>{escape(args)}</Arguments><WorkingDirectory>{escape(str(ROOT))}</WorkingDirectory></Exec></Actions>
</Task>'''
    fd, path = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    try:
        Path(path).write_text(xml, encoding="utf-16")
        subprocess.run(["schtasks.exe", "/Create", "/TN", name, "/XML", path, "/F"], check=True)
    finally:
        Path(path).unlink(missing_ok=True)
    print("Автозапуск при входе текущего пользователя включён (в том числе от батареи)")


def git(*args):
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Git: " + (result.stderr.strip() or result.stdout.strip()))
    return result.stdout.strip()


def verify_checkout(path):
    subprocess.run([str(python_console()), "-m", "py_compile", str(path / "battery_monitor.py")], check=True)
    subprocess.run([str(python_console()), "-m", "unittest", "discover", "-s", "tests", "-v"],
                   cwd=path, check=True)


def update():
    """Validate the fetched revision before stopping; keep user data outside this checkout."""
    if git("status", "--porcelain"):
        raise RuntimeError("В папке проекта есть локальные изменения. Сохраните их перед обновлением")
    old = git("rev-parse", "HEAD")
    upstream = git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    print("Получение обновлений…", flush=True)
    git("fetch", "--prune")
    target = git("rev-parse", upstream)
    git("merge-base", "--is-ancestor", old, target)
    if old == target:
        print("Установлена последняя версия")
        return
    with tempfile.TemporaryDirectory(prefix="battery-update-") as temporary:
        candidate = Path(temporary) / "candidate"
        git("worktree", "add", "--detach", str(candidate), target)
        try:
            print("Проверка новой версии…", flush=True)
            verify_checkout(candidate)
        finally:
            git("worktree", "remove", "--force", str(candidate))
    running = is_running()
    if running:
        stop_agent()
    try:
        # Required FF-only pull never discards local commits or edits.
        print(git("pull", "--ff-only"), flush=True)
        # The remote may have advanced since preflight: verify the installed revision as well.
        if git("rev-parse", "HEAD") != target:
            verify_checkout(ROOT)
    except Exception:
        if running and git("rev-parse", "HEAD") == old:
            start_agent()
        else:
            print("Обновление не прошло проверку. Агент оставлен остановленным; настройки сохранены", file=sys.stderr)
        raise
    if running:
        # Start with new source code, not functions already imported by this updater.
        subprocess.run([str(python_console()), str(ROOT / "battery_monitor.py"), "start"], check=True)
    print("Обновлено до " + git("rev-parse", "--short", "HEAD"))


def authenticate(args):
    require_windows()
    if args.client_id:
        webbrowser.open("https://oauth.yandex.ru/authorize?" + urlencode({
            "response_type": "token", "client_id": args.client_id,
            "scope": "cloud_api:disk.app_folder"}))
        print("Разрешите доступ к папке приложения и скопируйте OAuth-токен")
    token = sys.stdin.readline().strip() if args.stdin else getpass.getpass("OAuth-токен (ввод скрыт): ")
    if not token or any(c.isspace() for c in token):
        raise ValueError("Неверный формат токена")
    DiskClient(token).test()  # Keep the old token if the new one is invalid.
    save_token(token)
    # Wake a running agent immediately, without placing the secret in the request.
    if is_running():
        write_json(data_dir() / "send.request", {"id": uuid.uuid4().hex})
    print("Подключено. Токен защищён Windows DPAPI для текущего пользователя")


def show_status(as_json=False):
    config = load_config()
    value = {"running": is_running(), "installed_version": VERSION,
             "data_directory": str(data_dir()), "config": config,
             "token_configured": (data_dir() / "token.dat").exists(),
             "agent": read_json(data_dir() / "status.json", {})}
    try:
        value["current_battery"] = battery_status()
    except (RuntimeError, OSError) as exc:
        value["battery_error"] = str(exc)
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2))
    else:
        print("Агент: " + ("работает" if value["running"] else "остановлен"))
        print("Компьютер: " + socket.gethostname())
        print("Название: " + (config["display_name"] or socket.gethostname()))
        print("Версия: " + VERSION + "; интервал: " + str(config["interval"]) + " с")
        battery = value.get("current_battery", {})
        print("Заряд: " + (str(battery["battery_percent"]) + "%" if battery.get("battery_percent") is not None else "нет данных / батареи"))
        print("Последняя отправка: " + str(value["agent"].get("last_success_at") or "ещё не выполнялась"))
        print("Ошибка: " + str(value["agent"].get("last_error") or "нет"))
        print("Данные: " + str(data_dir()))


def logs(follow=False, bootstrap=False):
    path = data_dir() / ("bootstrap.log" if bootstrap else "agent.log")
    if not path.exists():
        print("Журнал пока пуст")
        return
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    print("\n".join(lines[-50:]))
    position = path.stat().st_size
    while follow:
        time.sleep(0.5)
        if not path.exists():
            continue
        if path.stat().st_size < position:
            position = 0
        with path.open("rb") as stream:
            stream.seek(position)
            chunk = stream.read()
            position = stream.tell()
        if chunk:
            print(chunk.decode("utf-8", errors="replace"), end="", flush=True)


def parser():
    result = argparse.ArgumentParser(description="Заряд ноутбуков → Яндекс Диск. Управление фоновым агентом.")
    sub = result.add_subparsers(dest="command")
    for command in ("start", "stop", "restart", "send", "update", "version", "help", "run", "dashboard"):
        sub.add_parser(command)
    setup = sub.add_parser("setup", help="Пошаговая установка")
    setup.add_argument("--client-id")
    auth = sub.add_parser("auth", help="Подключить Яндекс Диск")
    auth.add_argument("--client-id", help="Client ID OAuth-приложения; открыть страницу выдачи токена")
    auth.add_argument("--stdin", action="store_true", help="Прочитать токен из stdin")
    status = sub.add_parser("status")
    status.add_argument("--json", action="store_true")
    test = sub.add_parser("test")
    test.add_argument("--json", action="store_true")
    log = sub.add_parser("logs")
    log.add_argument("--follow", action="store_true")
    log.add_argument("--bootstrap", action="store_true")
    auto = sub.add_parser("autostart")
    auto.add_argument("action", choices=["enable", "disable", "status"])
    config = sub.add_parser("config")
    config_sub = config.add_subparsers(dest="action", required=True)
    show = config_sub.add_parser("show")
    show.add_argument("--json", action="store_true")
    setting = config_sub.add_parser("set")
    setting.add_argument("key", choices=CONFIG_KEYS)
    setting.add_argument("value")
    reset = config_sub.add_parser("reset")
    reset.add_argument("key", choices=CONFIG_KEYS)
    return result


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    if args.command in (None, "help"):
        cli.print_help()
    elif args.command == "version":
        print(VERSION)
    elif args.command == "run":
        run_agent()
    elif args.command == "start":
        start_agent()
    elif args.command == "stop":
        stop_agent()
    elif args.command == "restart":
        stop_agent()
        start_agent()
    elif args.command == "send":
        request_send()
    elif args.command == "status":
        show_status(args.json)
    elif args.command == "config":
        config = load_config()
        if args.action == "show":
            output = {**config, "token_configured": (data_dir() / "token.dat").exists()}
            if args.json:
                print(json.dumps(output, ensure_ascii=False, indent=2))
            else:
                for key, value in output.items():
                    print(f"{key}: {value}")
        else:
            key = CONFIG_KEYS[args.key]
            defaults = {"display_name": "", "interval": 300, "disk_path": DEFAULT_PATH}
            value = defaults[key] if args.action == "reset" else args.value
            if key == "interval":
                value = int(value)
            config[key] = value
            write_json(data_dir() / "config.json", validate_config(config))
            print("Настройка сохранена; работающий агент применит её автоматически")
    elif args.command == "auth":
        authenticate(args)
    elif args.command == "test":
        payload = snapshot(load_config())
        DiskClient(load_token()).test()
        print(json.dumps({"disk": "ok", "sample": payload}, ensure_ascii=False, indent=2)
              if args.json else "Получение заряда и доступ к Диску: OK")
    elif args.command == "autostart":
        autostart(args.action)
    elif args.command == "logs":
        logs(args.follow, args.bootstrap)
    elif args.command == "update":
        update()
    elif args.command == "dashboard":
        webbrowser.open((ROOT / "dashboard.html").as_uri())
    elif args.command == "setup":
        require_windows()
        config = load_config()
        answer = input(f"Название [{config['display_name'] or socket.gethostname()}], Enter — оставить: ").strip()
        if answer:
            config["display_name"] = answer
        answer = input(f"Интервал в секундах [{config['interval']}]: ").strip()
        if answer:
            config["interval"] = int(answer)
        write_json(data_dir() / "config.json", validate_config(config))
        if not (data_dir() / "token.dat").exists() or input("Заменить сохранённый токен? [y/N]: ").lower() == "y":
            authenticate(argparse.Namespace(client_id=args.client_id, stdin=False))
        else:
            DiskClient(load_token()).test()
        if input("Включить автозапуск при входе в Windows? [Y/n]: ").lower() != "n":
            autostart("enable")
        start_agent()
        print("Откройте dashboard.html и подключите тот же Диск")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nПрервано", file=sys.stderr)
        raise SystemExit(130)
    except (RuntimeError, ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print("Ошибка: " + str(error), file=sys.stderr)
        raise SystemExit(1)
