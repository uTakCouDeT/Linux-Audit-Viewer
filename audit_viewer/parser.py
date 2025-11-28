import re
from datetime import datetime
import pwd

AUDIT_LINE_RE = re.compile(r'^type=(\w+)\s+(.*)$')
FIELD_RE = re.compile(r'(\w+)=(".*?"|\S+)')
UNSET_AUID_VALUES = {"-1", "4294967295"}

def parse_audit_line(line: str):
    """
    Разбирает одну строку audit.log.
    Возвращает dict с полями:
    {
        "type": "SYSCALL" / "PATH" / ...,
        "timestamp": float или None,
        "event_id": int или None,
        "fields": { "uid": "...", "auid": "...", ... },
        "raw": исходная_строка
    }
    Если строка не подходит под формат auditd — возвращает None.
    """
    line = line.strip()
    if not line:
        return None

    m = AUDIT_LINE_RE.match(line)
    if not m:
        return None

    rec_type = m.group(1)
    rest = m.group(2)

    fields = {}
    for fm in FIELD_RE.finditer(rest):
        key = fm.group(1)
        value = fm.group(2)
        # убираем кавычки по краям, если есть
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1]
        fields[key] = value

    # Достаём timestamp и event_id из msg=audit(...)
    timestamp = None
    event_id = None
    msg_val = fields.get("msg")
    if msg_val and msg_val.startswith("audit("):
        # msg=audit(1732701601.123:24287)
        # убираем возможное двоеточие в конце
        msg_clean = msg_val.rstrip(":")
        m2 = re.match(r'audit\(([\d\.]+):(\d+)\)', msg_clean)
        if m2:
            try:
                timestamp = float(m2.group(1))
                event_id = int(m2.group(2))
            except ValueError:
                pass

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


def resolve_user(auid_str: str | None, uid_str: str | None) -> str:
    """
    Превращает auid/uid из лога в человекочитаемое значение:
    - пытается использовать auid, если он валиден,
    - иначе uid,
    - пытается получить имя пользователя через pwd.getpwuid,
    - корректно обрабатывает -1/4294967295 (unset).
    """
    # Берём приоритетно auid, если есть
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


def build_event_summary(event_records):
    """
    На основе списка record'ов (одного event_id) строим
    краткую сводку для таблицы и details/raw для нижней панели.
    Возвращает dict:
    {
        "time": ...,
        "user": ...,
        "event_type": ...,
        "comm": ...,
        "exe": ...,
        "success": bool,
        "key": ...,
        "details": { ... },
        "raw": "строки лога\n..."
    }
    """
    if not event_records:
        return None

    # timestamp возьмём из первого нормального
    ts = None
    for rec in event_records:
        if rec["timestamp"] is not None:
            ts = rec["timestamp"]
            break

    time_str = format_timestamp(ts) if ts is not None else ""

    # Найдём основной record: SYSCALL, если есть, иначе первый
    main_rec = None
    for rec in event_records:
        if rec["type"] == "SYSCALL":
            main_rec = rec
            break
    if main_rec is None:
        main_rec = event_records[0]

    f = main_rec["fields"]

    auid = f.get("auid")
    uid = f.get("uid")
    user = resolve_user(auid, uid)

    event_type = main_rec["type"]
    comm = f.get("comm", "")
    exe = f.get("exe", "")
    key = f.get("key", "")

    # success=yes/no/1/0 → bool
    success_val = f.get("success")
    success = None
    if success_val is not None:
        success = success_val in ("yes", "1", "true", "TRUE", "Yes")
    else:
        success = True  # если поля нет — считаем успешным

    # Собираем детали: просто объединяем все поля из всех records
    details = {}
    for rec in event_records:
        rtype = rec["type"]
        for k, v in rec["fields"].items():
            # Можно префиксовать типом, чтобы было видно, откуда поле:
            # details[f"{rtype}.{k}"] = v
            # но для простоты пока без префикса, если не конфликтует
            if k not in details:
                details[k] = v

    raw_lines = [rec["raw"] for rec in event_records]
    raw_text = "\n".join(raw_lines)

    return {
        "time": time_str,
        "timestamp": ts,
        "user": user,
        "event_type": event_type,
        "comm": comm,
        "exe": exe,
        "success": success,
        "key": key,
        "details": details,
        "raw": raw_text,
    }


def parse_audit_log_file(path: str):
    """
    Читает файл audit.log и возвращает список событий
    в формате, подходящем для AuditEventsTableModel.
    """
    events_by_id = {}  # event_id -> {"records": [], "timestamp": ...}

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            rec = parse_audit_line(line)
            if not rec:
                continue

            eid = rec["event_id"]
            if eid is None:
                # Строка без event_id — можно игнорировать или обрабатывать отдельно
                continue

            bucket = events_by_id.get(eid)
            if bucket is None:
                bucket = {"records": [], "timestamp": rec["timestamp"]}
                events_by_id[eid] = bucket

            bucket["records"].append(rec)
            # Если timestamp ещё не выставлен, обновляем
            if bucket["timestamp"] is None and rec["timestamp"] is not None:
                bucket["timestamp"] = rec["timestamp"]

    # Преобразуем во flat-список событий
    events = []
    for eid, bucket in events_by_id.items():
        event_records = bucket["records"]
        ev = build_event_summary(event_records)
        if ev:
            events.append(ev)

    # Можно отсортировать по времени (по строковому полю time)
    events.sort(key=lambda e: e["time"])

    return events
