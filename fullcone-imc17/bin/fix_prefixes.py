#!/usr/bin/env python3
import sys
old = ""
cache = set()
for line in sys.stdin:
    line = line.strip()
    try:
        a, b = line.split(": ")
        if a != old:
            for x in old.strip("{}").split(","):
                if x and cache:
                    print(x + ": " + ",".join(cache))
            cache = set()
            old = a
        cache.update(set(b.strip().split(",")))
    except Exception as e:
        print(line, e, file=sys.stderr)
        raise
    
for x in old.strip("{}").split(","):
    print(x + ": " + ",".join(cache))
