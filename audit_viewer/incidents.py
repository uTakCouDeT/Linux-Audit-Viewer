from collections import defaultdict
from datetime import datetime, timedelta


def _parse_ts(ev):
    """Достаём datetime из события, если есть."""
    ts = ev.get("timestamp")
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts)
    except Exception:
        return None


def find_ssh_bruteforce(events, min_failures=5, window_minutes=10):
    """
    Сценарий 1: попытки подбора пароля по SSH.

    Ищем серии неуспешных логинов (USER_AUTH/USER_LOGIN, success=False)
    для одного пользователя или одного IP за короткий интервал времени.
    """
    window = timedelta(minutes=window_minutes)

    # Группируем неуспешные попытки по (user, addr)
    buckets = defaultdict(list)

    for ev in events:
        etype = ev.get("event_type")
        if etype not in ("USER_AUTH", "USER_LOGIN"):
            continue

        if ev.get("success", True):
            continue  # нужны только ошибки

        details = ev.get("details", {})
        exe = details.get("exe", "") or ev.get("exe", "")
        # фильтруем по sshd / ssh
        if "ssh" not in exe:
            continue

        user = ev.get("user", "?")
        addr = details.get("addr") or details.get("addr4") or details.get("addr6") or "-"
        key = (user, addr)

        ts = _parse_ts(ev)
        if not ts:
            continue

        buckets[key].append((ts, ev))

    suspicious_events = []
    seen_ids = set()

    for (user, addr), items in buckets.items():
        # сортируем по времени
        items.sort(key=lambda x: x[0])
        times = [t for t, _ in items]

        n = len(times)
        left = 0
        for right in range(n):
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


def find_critical_file_changes(events):
    """
    Сценарий 2: изменения критичных файлов.

    Ищем SYSCALL/операции, где в details['name'] фигурируют важные файлы,
    и операция прошла успешно.
    """
    result = []

    for ev in events:
        etype = ev.get("event_type")
        if etype != "SYSCALL":
            continue

        if not ev.get("success", True):
            continue

        details = ev.get("details", {})
        path = details.get("name") or details.get("path")
        if not path:
            continue

        for critical in CRITICAL_PATHS:
            if path == critical or path.startswith(critical + "."):
                result.append(ev)
                break

    return result


SERVICE_UIDS = {"33", "48", "80"}  # www-data, apache/nginx и т.п. (можно расширять)
SHELL_NAMES = {"bash", "sh", "zsh"}
SHELL_EXES = {"/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"}


def find_web_shell(events):
    """
    Сценарий 3: запуск интерактивного shell от имени сервисного пользователя
    (www-data/nginx/apache и т.п.) — типовой индикатор web-shell.
    """
    result = []

    for ev in events:
        etype = ev.get("event_type")
        if etype != "SYSCALL":
            continue

        details = ev.get("details", {})

        # syscall = execve или его номер (59)
        syscall = details.get("syscall", "")
        if syscall not in ("execve", "59"):
            continue

        exe = ev.get("exe", "") or details.get("exe", "")
        comm = ev.get("comm", "") or details.get("comm", "")

        # проверяем, что запускается shell
        if exe in SHELL_EXES:
            is_shell = True
        elif comm in SHELL_NAMES:
            is_shell = True
        else:
            is_shell = False

        if not is_shell:
            continue

        uid_raw = details.get("uid") or ""
        numeric_uid = uid_raw.split()[0] if uid_raw else ""
        # сервисный uid?
        if numeric_uid not in SERVICE_UIDS:
            # fallback: по строке user
            user_str = ev.get("user", "")
            lowered = user_str.lower()
            if not any(x in lowered for x in ("www-data", "nginx", "apache")):
                continue

        result.append(ev)

    return result
