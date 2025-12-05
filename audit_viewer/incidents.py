from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import re


def _parse_ts(ev: Dict[str, Any]) -> Optional[datetime]:
    """Достаём datetime из события, если есть."""
    ts = ev.get("timestamp")
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts)
    except Exception:
        return None


def _details_get_first(details: Dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Безопасно достаёт первое значение поля из details:
    - если там строка → возвращает строку;
    - если список → первый элемент;
    - если нет ключа → default.
    """
    val = details.get(key, default)
    if isinstance(val, list):
        if val:
            return val[0]
        return default
    return val


def _details_get_first_str(details: Dict[str, Any], key: str, default: str = "") -> str:
    """То же самое, но сразу приводит к строке (если есть)."""
    val = _details_get_first(details, key, None)
    if val is None:
        return default
    return str(val)


def find_ssh_bruteforce(
        events: List[Dict[str, Any]],
        min_failures: int = 5,
        window_minutes: int = 10,
) -> List[Dict[str, Any]]:
    """
    Сценарий 1: попытки подбора пароля по SSH.

    Ищем серии неуспешных логинов (USER_AUTH/USER_LOGIN, success=False)
    для одного пользователя или одного IP за короткий интервал времени.
    """
    window = timedelta(minutes=window_minutes)

    # Группируем неуспешные попытки по (user, addr)
    buckets: Dict[Tuple[str, str], List[Tuple[datetime, Dict[str, Any]]]] = defaultdict(list)

    for ev in events:
        etype = ev.get("event_type")
        if etype not in ("USER_AUTH", "USER_LOGIN"):
            continue

        # нас интересуют именно явные ошибки
        if ev.get("success") is not False:
            continue  # success True или None — пропускаем

        details = ev.get("details", {}) or {}

        # exe из summary, при отсутствии — из details
        exe = ev.get("exe") or _details_get_first_str(details, "exe", "")
        exe_lower = exe.lower()

        # фильтруем по sshd / ssh
        if "ssh" not in exe_lower:
            continue

        user = ev.get("user", "?")
        # addr может быть строкой или списком, берём первое значение
        addr = (
                _details_get_first_str(details, "addr")
                or _details_get_first_str(details, "addr4")
                or _details_get_first_str(details, "addr6")
                or "-"
        )

        key = (user, addr)

        ts = _parse_ts(ev)
        if not ts:
            continue

        buckets[key].append((ts, ev))

    suspicious_events: List[Dict[str, Any]] = []
    seen_ids = set()

    for (user, addr), items in buckets.items():
        # сортируем по времени
        items.sort(key=lambda x: x[0])
        times = [t for t, _ in items]

        n = len(times)
        left = 0
        for right in range(n):
            # сдвигаем левую границу окна
            while left < right and times[right] - times[left] > window:
                left += 1

            if right - left + 1 >= min_failures:
                # добавляем все события из этого окна, без дублей
                for i in range(left, right + 1):
                    ev = items[i][1]
                    ev_id = id(ev)
                    if ev_id not in seen_ids:
                        seen_ids.add(ev_id)
                        suspicious_events.append(ev)

    return suspicious_events


CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
]


def find_critical_file_changes(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Сценарий 2: изменения критичных файлов.

    Ищем SYSCALL/операции, где в details['name'] фигурируют важные файлы,
    и операция прошла успешно.
    """
    result: List[Dict[str, Any]] = []

    for ev in events:
        etype = ev.get("event_type")
        if etype != "SYSCALL":
            continue

        # интересуют только явно успешные операции
        if ev.get("success") is not True:
            continue

        details = ev.get("details", {}) or {}

        # name/path может быть строкой или списком
        path_val = details.get("name") or details.get("path")
        if not path_val:
            continue

        if isinstance(path_val, list):
            paths = [str(p) for p in path_val if p]
        else:
            paths = [str(path_val)]

        found = False
        for p in paths:
            for critical in CRITICAL_PATHS:
                if p == critical or p.startswith(critical + "."):
                    result.append(ev)
                    found = True
                    break
            if found:
                break

    return result


SERVICE_UIDS = {"33", "48", "80", "999"}  # можно вручную записать необходимые uid-ы

SHELL_NAMES = {"bash", "sh", "zsh"}
SHELL_EXES = {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}

# типичные имена сервисных / веб-юзеров
SERVICE_USER_NAME_TOKENS = (
    "www-data",
    "nginx",
    "apache",
    "www",
    "http",
    "httpd",
    "lighttpd",
    "zabbix",
    "wwwrun",
)


def _extract_uid_name(uid_str: str) -> str:
    """
    Из строки вида '972 (nginx)' достаёт 'nginx'.
    Если скобок нет — возвращает пустую строку.
    """
    m = re.search(r"\(([^)]+)\)", uid_str)
    if m:
        return m.group(1)
    return ""


def _looks_like_service_name(name: str) -> bool:
    """Проверяет, похоже ли имя на сервисного / веб-пользователя."""
    name = name.lower()
    return any(tok in name for tok in SERVICE_USER_NAME_TOKENS)


def _is_service_user(ev: Dict[str, Any], details: Dict[str, Any]) -> bool:
    """
    Пытается определить, что событие идёт от сервисного / веб-пользователя:
    1) по имени (uid-name, acct, user, UID);
    2) по ручному списку UID (SERVICE_UIDS);
    3) по диапазону UID (1–999) как мягкая эвристика.
    """
    # 1. Пытаемся найти любые имена
    uid_str = _details_get_first_str(details, "uid", "")
    uid_name = _extract_uid_name(uid_str)

    acct = _details_get_first_str(details, "acct", "").lower()
    user_summary = (ev.get("user") or "").lower()
    uid_upper = _details_get_first_str(details, "UID", "").lower()  # из твоих логов

    for candidate in (uid_name, acct, user_summary, uid_upper):
        if candidate and _looks_like_service_name(candidate):
            return True

    # 2. Чистый numeric UID и ручной whitelist
    numeric_uid = uid_str.split()[0] if uid_str else ""
    if numeric_uid in SERVICE_UIDS:
        return True

    # 3. Мягкая эвристика по диапазону UID
    try:
        uid_int = int(numeric_uid)
    except (TypeError, ValueError):
        return False

    # 0 — root, отдельно, здесь считаем, что данный сценарий не про root
    if uid_int == 0:
        return False

    # 1–999 — системные/сервисные аккаунты → считаем сервисным
    if 1 <= uid_int < 1000:
        return True

    return False


def find_web_shell(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Сценарий 3: запуск интерактивного shell от имени сервисного пользователя
    (www-data/nginx/apache и т.п.) — типовой индикатор web-shell.
    """
    result: List[Dict[str, Any]] = []

    for ev in events:
        etype = ev.get("event_type")
        if etype != "SYSCALL":
            continue

        details = ev.get("details", {}) or {}

        # syscall = execve или его номер (59)
        syscall = ev.get("syscall") or _details_get_first_str(details, "syscall", "")
        syscall_str = str(syscall)

        if syscall_str not in ("execve", "59"):
            continue

        # exe / comm: сначала summary, затем details
        exe = ev.get("exe") or _details_get_first_str(details, "exe", "")
        comm = ev.get("comm") or _details_get_first_str(details, "comm", "")

        # проверяем, что запускается shell
        if exe in SHELL_EXES or comm in SHELL_NAMES:
            is_shell = True
        else:
            is_shell = False

        if not is_shell:
            continue

        # Определяем, что пользователь сервисный / веб
        if not _is_service_user(ev, details):
            continue

        result.append(ev)

    return result
