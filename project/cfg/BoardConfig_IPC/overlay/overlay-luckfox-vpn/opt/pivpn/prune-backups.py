#!/usr/bin/python3
from pathlib import Path
import re
import sys


def prune(directory, keep, current):
    pattern = re.compile(r"pivpnbackup-([0-9]{8}-[0-9]{6})(?:-([1-9][0-9]*))?\.tgz\Z")
    files = [p for p in directory.iterdir()
             if pattern.fullmatch(p.name) and not p.is_symlink() and p.is_file()]
    def order(path):
        match = pattern.fullmatch(path.name)
        return path == current, path.stat().st_mtime_ns, match[1], int(match[2] or 0)
    files.sort(key=order, reverse=True)
    for path in files[keep:]:
        path.unlink()


if __name__ == "__main__":
    try:
        prune(Path(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3]))
    except (OSError, ValueError) as error:
        print("::: Backup retention failed (" + type(error).__name__ + ")", file=sys.stderr)
        sys.exit(1)
