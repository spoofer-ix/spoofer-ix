#!/usr/bin/env python3
import sys
old = ""
cache = set()
for line in sys.stdin:
    line = line.strip()
    try:
        a, b = line.split(": ")
        if a != old:
            if old and cache:
                print(old + ": " + ",".join(cache))
            cache = set()
            old = a
        cache.update(set(b.strip().split(",")))
    except Exception as e:
        print(line, e, file=sys.stderr)
        raise
print(old + ": " + ",".join(cache))
