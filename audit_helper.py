#!/usr/bin/env python3
import sys
import json
from pathlib import Path

from audit_viewer.parser import parse_audit_log_file


def main():
    log_path = Path("/var/log/audit/audit.log")
    if not log_path.exists():
        print(json.dumps({"error": "log_not_found"}))
        return 1

    try:
        events = parse_audit_log_file(str(log_path))
    except Exception as e:
        print(json.dumps({"error": "parse_error", "message": str(e)}))
        return 1

    print(json.dumps({"events": events}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
