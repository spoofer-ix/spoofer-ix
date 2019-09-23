#!/usr/bin/env python3
import sys

for line in sys.stdin:
    a, b = line.split()
    [[print("%s %s" % (x, y)) for y in b.strip("{}").split(",")] for x in a.strip("{}").split(",")]

