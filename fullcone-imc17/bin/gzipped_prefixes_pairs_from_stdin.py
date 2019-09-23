#!/usr/bin/env python3

from sys import argv, stdin, stderr, exit
import time
import gzip
import os.path as path
from os import makedirs, rename

WORKDIR="/tmp"

PAIRSDIR=path.join(WORKDIR, "pairs")
PREFSDIR=path.join(WORKDIR, "prefixes")
PATHSDIR=path.join(WORKDIR, "paths")

if len(argv) < 2:
    print("no output filename specified", file=stderr)
    exit(1)


PAIRSFNAME=path.join(PAIRSDIR, argv[1] + ".gz")
PREFSFNAME=path.join(PREFSDIR, argv[1] + ".gz")
PATHSFNAME=path.join(PATHSDIR, argv[1] + ".gz")

PAIRS = not path.exists(PAIRSFNAME)
PREFS = not path.exists(PREFSFNAME)
PATHS = not path.exists(PATHSFNAME)

#conecommands = "".join(["%s %s\n" % (cmd, path) for cmd, path in zip(["zpairs", "zprefixes", "zpaths"], [PAIRSFNAME, PREFSFNAME, PATHSFNAME])])

#not PAIRS and not PREFS and not PATHS and print("all data for %s already collected" % argv[1], file=stderr) and exit(0) #and print(conecommands) exit(0)

makedirs(PAIRSDIR, exist_ok=True)
makedirs(PREFSDIR, exist_ok=True)
makedirs(PATHSDIR, exist_ok=True)


pairs = set()
ASN2Prefixes = {}
Prefix2ASNs = {}

s = time.time()

def stopwatch(s, start=time.time()):
    now = time.time()
    print(s + ":", now - start, "seconds", file=stderr)
    return now

#BGP4MP|1483228808|A|146.228.1.3|1836|203.77.197.0/24|1836 174 6453 4755 45117 45117 17913|IGP|146.228.1.3|0|0|1836:110 1836:6000 1836:6031|NAG||

done = False
while not done:
    try:
        for line in stdin:
            tokens = line.split("|")
            # ignore route withdrawals
            if len(tokens) < 7 or tokens[2] not in ["A","B"]:
                continue
            asns = tokens[6].split()
            prefix = tokens[5]
            _, net = prefix.split("/")
            net = int(net)
            #ignore v6 and empty AS paths or too small/large nets
            if not asns or net < 8 or net > 24 or ":" in prefix:
                continue
            if PAIRS:
                #sourceASN = tokens[4]
                #if asns[0] == sourceASN:
                #pairs.update(zip(asns[1::1], asns[2::1]))
                #else:
                pairs.update(zip(asns[0::1], asns[1::1]))
            if PREFS:
                source = asns[-1]
                for source in asns[-1].strip("{}").split(","):
					# if source not in ASN2Prefixes:
					#    ASN2Prefixes[source] = set()
					# ASN2Prefixes[source].add(prefix)
                    ASN2Prefixes.setdefault(source, set()).add(prefix)
            if PATHS:
                # deal with AS sets, put every ASset-member into path
                Prefix2ASNs.setdefault(prefix, set()).update(*map(lambda asn: asn.strip("{}").split(","), asns))
        done = True
    except Exception as e:
        print(e, argv[1], file=stderr)
        exit(1)
        
tmp = []
PAIRS and tmp.append("pairs")
PREFS and tmp.append("prefs")
PATHS and tmp.append("paths")

s = stopwatch("generated %s" % (((tmp and ", ".join(tmp[0:-1]) or "") + (len(tmp) > 1 and " and " or "")) + (tmp and tmp[-1] or "nothing")), s)

if PAIRS and pairs:
    with gzip.open(PAIRSFNAME+".tmp", 'wt') as f:
        for a, b in pairs:
            [[print("%s %s" % (x, y), file=f) for y in b.strip("{}").split(",")] for x in a.strip("{}").split(",")]
    rename(PAIRSFNAME+".tmp", PAIRSFNAME)
    s = stopwatch("wrote gzipped pairs to %s" % PAIRSFNAME, s)

if PREFS and ASN2Prefixes:
    with gzip.open(PREFSFNAME+".tmp", 'wt') as f:
        for asn, prefixes in ASN2Prefixes.items():
            print(asn+":", ",".join(prefixes), file=f)
    rename(PREFSFNAME+".tmp", PREFSFNAME)
    s = stopwatch("wrote gzipped prefixes to %s" % PREFSFNAME, s)

if PATHS and Prefix2ASNs:
    with gzip.open(PATHSFNAME, 'wt') as f:
        for prefix, asns in Prefix2ASNs.items():
            print(prefix+":", ",".join(asns), file=f)
    s = stopwatch("wrote gzipped paths to %s" % PATHSFNAME, s)


        
#print(conecommands)
