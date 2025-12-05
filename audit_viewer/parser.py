from __future__ import annotations

import re
from datetime import datetime
from collections import Counter
import pwd
from typing import Any, Dict, List, Optional, Tuple

# Специальные значения для "неустановленного" auid
UNSET_AUID_VALUES = {"-1", "4294967295"}

# --- Регулярные выражения для разбора строк журнала auditd ---
AUDIT_LINE_RE = re.compile(
    r'^type=(?P<type>\S+)\s+msg=audit\((?P<ts>[\d\.]+):(?P<eid>\d+)\):\s*(?P<data>.*)$'
)
FIELD_RE = re.compile(r'([A-Za-z0-9_]+)=(".*?"|\S+)')


def parse_audit_line(line: str):
    line = line.strip()
    if not line:
        return None

    m = AUDIT_LINE_RE.match(line)
    if not m:
        return None

    rec_type = m.group("type")
    ts_str = m.group("ts")
    eid_str = m.group("eid")
    data = m.group("data") or ""

    try:
        timestamp = float(ts_str)
    except ValueError:
        timestamp = None

    try:
        event_id = int(eid_str)
    except ValueError:
        event_id = None

    fields = {}
    for fm in FIELD_RE.finditer(data):
        key = fm.group(1)
        value = fm.group(2)

        # 1) убираем парные кавычки "..." или '...'
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        else:
            # 2) типичный артефакт: res=failed'
            #    убираем висящую одинокую кавычку в конце
            if value.endswith("'"):
                value = value[:-1]

        fields[key] = value

    return {
        "type": rec_type,
        "timestamp": timestamp,
        "event_id": event_id,
        "fields": fields,
        "raw": line,
    }


def format_timestamp(ts: float) -> str:
    """Преобразует unixtime в строку 'YYYY-MM-DD HH:MM:SS'."""
    try:
        dt = datetime.fromtimestamp(ts)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


def resolve_user(auid_str: Optional[str], uid_str: Optional[str]) -> str:
    """
    Превращает auid/uid из лога в человекочитаемое значение:

    - приоритетно использует auid, если он валиден;
    - иначе uid;
    - пытается получить имя пользователя через pwd.getpwuid;
    - корректно обрабатывает -1/4294967295 (unset).

    Возвращает строку вида:
        - "unset"
        - "root (0)"
        - "username (1000)"
        - "1001" (если UID не найден в системе)
        - исходное значение, если его нельзя привести к int.
    """
    raw = auid_str or uid_str
    if raw is None:
        return "?"

    raw = str(raw)

    # unset значения
    if raw in UNSET_AUID_VALUES:
        return "unset"

    # бывает вида "1000" или "1000 (ivan)" — отрежем всё после пробела
    numeric_part = raw.split()[0]

    try:
        uid_val = int(numeric_part)
    except ValueError:
        # это уже не чистый uid, вернём как есть
        return raw

    # uid = 0 — root
    if uid_val == 0:
        return "root (0)"

    # пытаемся найти имя пользователя
    try:
        pw = pwd.getpwuid(uid_val)
        return f"{pw.pw_name} ({uid_val})"
    except KeyError:
        # нет такого uid в системе
        return f"{uid_val}"


def _merge_fields_to_details(event_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Собирает все поля из всех record'ов события в один словарь details.

    Если ключ встречается несколько раз (например, несколько PATH/name),
    значения агрегируются в список. Это важно для корректного анализа
    изменений нескольких файлов в рамках одного события.
    """
    details: Dict[str, Any] = {}

    for rec in event_records:
        for k, v in rec["fields"].items():
            if k in details:
                # уже есть значение → агрегируем в список
                if isinstance(details[k], list):
                    details[k].append(v)
                else:
                    details[k] = [details[k], v]
            else:
                details[k] = v

    return details


def _choose_main_record(event_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Выбирает "основную" запись события, на основе которой формируется summary.

    Приоритет:
        1) SYSCALL  — для системных вызовов и файловых операций;
        2) USER_AUTH / USER_LOGIN — для аутентификации и логинов;
        3) первая запись в списке.
    """
    # 1. SYSCALL
    for rec in event_records:
        if rec["type"] == "SYSCALL":
            return rec

    # 2. USER_AUTH / USER_LOGIN
    for rec in event_records:
        if rec["type"] in ("USER_AUTH", "USER_LOGIN"):
            return rec

    # 3. fallback: первая запись
    return event_records[0]


def build_event_summary(event_records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    На основе списка record'ов (одного события) строит краткую сводку
    для таблицы и details/raw для нижней панели.

    Возвращает dict:
        {
            "time": ...,
            "timestamp": ...,
            "user": ...,
            "event_type": ...,
            "comm": ...,
            "exe": ...,
            "pid": ...,
            "ppid": ...,
            "syscall": ...,
            "exit": ...,
            "cwd": ...,
            "success": bool | None,
            "key": ...,
            "details": { ... },
            "raw": "строки лога\n..."
        }
    """
    if not event_records:
        return None

    # timestamp возьмём как минимальный ненулевой из всех записей события
    ts: Optional[float] = None
    for rec in event_records:
        if rec["timestamp"] is not None:
            if ts is None or rec["timestamp"] < ts:
                ts = rec["timestamp"]

    time_str = format_timestamp(ts) if ts is not None else ""

    # выбираем основной record
    main_rec = _choose_main_record(event_records)
    f = main_rec["fields"]

    # пользователь
    auid = f.get("auid")
    uid = f.get("uid")
    user = resolve_user(auid, uid)

    event_type = main_rec["type"]
    comm = f.get("comm", "")
    exe = f.get("exe", "")

    # дополнительные "верхнеуровневые" поля, полезные в таблице
    pid = f.get("pid")
    ppid = f.get("ppid")
    syscall = f.get("syscall")
    exit_code = f.get("exit")
    cwd = f.get("cwd")
    tty = f.get("tty")
    acct = f.get("acct")
    addr = f.get("addr") or f.get("addr4") or f.get("addr6")
    hostname = f.get("hostname") or f.get("node")

    key = f.get("key", "")

    # success=yes/no/1/0 → bool
    # либо res=success/failed → bool
    success: Optional[bool] = None
    success_val = f.get("success")
    if success_val is not None:
        val = str(success_val).lower()
        success = val in ("yes", "1", "true", "ok")
    else:
        res_val = f.get("res")
        if res_val is not None:
            val = str(res_val).lower()
            if val in ("success", "ok", "1"):
                success = True
            elif val in ("failed", "fail", "error", "0"):
                success = False
        # если нет ни success, ни res — оставляем None

    # Собираем детали (с учётом повторяющихся ключей)
    details = _merge_fields_to_details(event_records)

    raw_lines = [rec["raw"] for rec in event_records]
    raw_text = "\n".join(raw_lines)

    return {
        "time": time_str,
        "timestamp": ts,
        "user": user,
        "event_type": event_type,
        "comm": comm,
        "exe": exe,
        "pid": pid,
        "ppid": ppid,
        "syscall": syscall,
        "exit": exit_code,
        "cwd": cwd,
        "tty": tty,
        "acct": acct,
        "addr": addr,
        "hostname": hostname,
        "success": success,
        "key": key,
        "details": details,
        "raw": raw_text,
    }


def parse_audit_log_file(path: str) -> List[Dict[str, Any]]:
    """
    Разбирает файл журнала auditd и возвращает список событий
    в нормализованном виде (подходящем для GUI, сценариев инцидентов и статистики).

    Каждое событие — это dict, возвращаемый build_event_summary().
    """
    # ключ: (node, event_id, ts_bucket)
    #   node      — поле node=... (если есть)
    #   event_id  — идентификатор события из audit(...)
    #   ts_bucket — секунда таймстампа (для снижения риска коллизий)
    events_by_id: Dict[Tuple[Optional[str], int, int], Dict[str, Any]] = {}

    total_lines = 0
    matched_lines = 0
    skipped_no_match = 0
    skipped_no_event_id = 0
    type_counter: Counter[str] = Counter()

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            rec = parse_audit_line(line)
            if not rec:
                skipped_no_match += 1
                continue

            matched_lines += 1
            type_counter[rec["type"]] += 1

            eid = rec["event_id"]
            ts = rec["timestamp"]
            if eid is None:
                skipped_no_event_id += 1
                continue

            fields = rec.get("fields", {})
            node = fields.get("node")  # для многомашинной агрегации

            ts_bucket = int(ts) if ts is not None else 0
            key = (node, eid, ts_bucket)

            bucket = events_by_id.get(key)
            if bucket is None:
                bucket = {"records": [], "timestamp": ts}
                events_by_id[key] = bucket

            bucket["records"].append(rec)
            # timestamp события — минимальный ненулевой ts среди record'ов
            if ts is not None:
                if bucket["timestamp"] is None or ts < bucket["timestamp"]:
                    bucket["timestamp"] = ts

    # Преобразуем во flat-список событий
    events: List[Dict[str, Any]] = []
    for key, bucket in events_by_id.items():
        event_records = bucket["records"]
        ev = build_event_summary(event_records)
        if ev:
            events.append(ev)

    # сортируем события по времени (от новых к старым)
    events.sort(key=lambda e: e.get("timestamp") or 0.0, reverse=True)

    # при необходимости можно раскомментировать отладочную статистику:
    # print(f"[parser] file: {path}")
    # print(f"[parser] total lines          : {total_lines}")
    # print(f"[parser] matched audit lines  : {matched_lines}")
    # print(f"[parser] skipped (no match)   : {skipped_no_match}")
    # print(f"[parser] skipped (no event_id): {skipped_no_event_id}")
    # print(f"[parser] resulting events     : {len(events)}")
    # print("[parser] top types:")
    # for t, cnt in type_counter.most_common(10):
    #     print(f"  {t:20s} {cnt}")

    return events


__all__ = [
    "parse_audit_line",
    "format_timestamp",
    "resolve_user",
    "build_event_summary",
    "parse_audit_log_file",
]
