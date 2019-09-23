#!/usr/bin/env python3

import sys
import time
import gzip
import pickle
import trie
import cmd
import os

from subprocess import Popen, PIPE

def zcat(filename):
    with Popen("zcat " + filename, shell=True, stdout=PIPE, bufsize=10485760) as pipe:
        for line in map(lambda x: x.decode("utf8").strip(), pipe.stdout):
            yield line


class CLI(cmd.Cmd):
    intro = "Welcome to the awesome cone cli. Type help or ? to list commands."
    prompt = "\n(cone) "

    def __init__(self):
        cmd.Cmd.__init__(self)
        self.tree = Tree()
        self.start = time.time()

    @staticmethod
    def debug(*args):
        print(*args, file=sys.stderr)

    def precmd(self, line):
        self.start = time.time()
        return line

    def postcmd(self, stop, line):
        self.debug("('" + line + "' completed after", time.time() - self.start, "seconds)")
        return stop

    def do_zpairs(self, arg):
        "load gzipped pairs file into cone"
        for line in zcat(arg):
            #print(line)
            self.tree.ParsePairs(line)
        #Node(0).fixEverything()
        self.tree.Bake()

    def do_zprefixes(self, arg):
        "load gzipped prefixes text file into cone"
        for line in zcat(arg):
            ASNs, prefixlist = line.split(": ")
            for ASN in ASNs.strip("{}").split(","):
                try:
                    ASN = int(ASN)
                    if not ASN in self.tree.nodes:
                        continue
                except ValueError as e:
                    self.debug(arg, line, e)
                    continue
                for prefix in prefixlist.split(","): #filter(lambda prefix: not ":" in prefix, prefixlist.split(",")):
                    self.tree.trie.addSubnet(prefix, self.tree.nodes[ASN])


    def do_zpaths(self, arg):
        "load gzipped paths text file into cone"
        for line in zcat(arg):
            try:
                prefix, ASNs = line.split(": ")
                self.tree.paths.addSubnetValues(prefix, filter(None, map(lambda x: self.tree.nodes.get(int(x)), ASNs.split(","))))
            except Exception as e:
                self.debug(line, e)
                continue

    """def do_validIPforASN(self, arg):
        ip, asn = arg.split()
        if int(asn) in self.tree.nodes:
            if self.tree.trie.lookUpIP(ip).intersection(self.tree.nodes[int(asn)].getCone()):
                print("%s is in cone of %s" % (ip, asn))
            else:
                print("%s is NOT IN cone of %s" % (ip, asn))
        else:
            print("we don't know AS %s" % asn)"""

    def do_validIPforASN(self, arg):
        ip, asn = arg.split()
        if self.tree.Cone(asn).isdisjoint(self.tree.trie.lookUpIP(ip)):
            print("%s is NOT IN cone of %s" % (ip, asn))
        else:
            print("%s is in cone of %s" % (ip, asn))

    def do_cone(self, arg):
        "return list of all ASNs in cone of given ASN"
        if int(arg) in self.tree.nodes:
            print(" ".join([str(node.ASN) for node in self.tree.nodes[int(arg)].getCone()]))
        else:
            print("ASN %s is not known", arg, file=sys.stderr)

    def do_cones(self, arg):
        "write list of all cones"
        with gzip.open(arg, "wt") as f:
            for n in sorted(self.tree.nodes):
                print(str(n)+" "+" ".join([str(node.ASN) for node in sorted(self.tree.nodes[n].getCone(), key=str)]), file=f)


    def do_24subnets(self, arg):
        with gzip.open(arg, "wt") as f:
            for first in range(0,256):
                for second in range(0,256):
                    for third in range(0,256):
                        prefix = "%d.%d.%d" % (first, second, third)
                        s = self.tree.trie.lookUpIP(prefix+".1")
                        print(prefix + ":", ",".join(map(str, s)), file=f)

    def do_origins(self, arg):
        "write contents of trie to gzipped file"
        with gzip.open(arg, "wt") as f:
            for line in self.tree.trie.lines():
                print(line, file=f)


    def do_pickle(self, arg):
        self.tree.Pickle(arg)

    def do_load(self, arg):
        "load pickled file"
        self.tree.Load(arg)

    def do_bake(self, _):
        "clear out temporary datastructures, thereby baking the cone into its current state"
        self.tree.Bake()

    #def do_merge(self, arg):
    #    "merge pickle file into current cone (ALPHA, UNTESTED)"
    #    self.tree.Merge(arg)


    def do_clear(self, _):
        self.debug("forgetting current state")
        self.tree = Tree()

    def do_stats(self, arg):
        with gzip.open(arg, "wt") as f:
            self.tree.trie.buildCache()
            for asn in sorted(self.tree.nodes.keys()):
                node = self.tree.nodes[asn]
                print(node, self.tree.trie.uniqueIPs(node), file=f)

    def do_exit(self, _):
        "exit gracefully"
        self.debug("cleaning up memory (may take a long time, Ctrl+C to let the OS deal with it)")
        sys.exit(0)


    def do_shell(self, arg):
        "run a shell command"
        with os.popen(arg) as pipe:
            for line in pipe:
                print(line.strip())

    def do_EOF(self, _):
        self.do_exit(_)

    def do_quit(self, _):
        self.do_exit(_)

    def do_uniqueIPs(self, _):
        self.trie.buildCache()
        for asn in sorted(self.tree.nodes.keys()):
            node = self.tree.nodes[asn]
            print(node, self.tree.trie.uniqueIPs(node))

class Tree():
#    nodes = {}
#    edges = 0
#    updates = 0
#    trie = trie.Trie()

    def __init__(self):
        self.nodes = {}
        self.trie = trie.Trie()
        self.paths = trie.Trie()

    def getOrAdd(self, ASN):
        # deal with potential AS set
        l = [self.nodes.setdefault(int(asn), Node(int(asn))) for asn in ASN.strip("{}").split(",")]
        if len(l) > 1:
            # we got an AS set, fully mesh all nodes in it
            [[x != y and x.addDownStream(y) for x in l] for y in l]
        return l

    def Add(self, ASPath, subnetstr=None):
        if ASPath:
            upstream = self.getOrAdd(ASPath[0])
            next = self.Add(ASPath[1:], subnetstr)
            if next:
                [[x.addDownStream(n) for n in next] for x in upstream]
            elif subnetstr:
                [self.trie.addSubnet(subnetstr, x) for x in upstream]
            return upstream
        return

    def AddPair(self, ASN1, ASN2):
        #self.updates += 1
        a1s = self.getOrAdd(ASN1)
        a2s = self.getOrAdd(ASN2)
        for a1 in a1s:
            for a2 in a2s:

                a1.addDownStream(a2)
             
    def ParseDumpLine(self, line):
        try:
            tokens = line.split("|")
            prefix = tokens[5]
            if ":" in prefix:
                return
            asns = tokens[6].split()
            #self.Add(asns)
            self.Add(asns, prefix)
        except IndexError as e:
            print("parse error", e, file=sys.stderr)
            
    def ParsePairs(self, line):
        try:
            asn1, asn2 = line.split()
            self.AddPair(asn1, asn2)
        except ValueError as e:
            print("parse error", e, file=sys.stderr)

    def Load(self, filename):
        with gzip.open(filename, "rb") as f:
            self.nodes, self.trie, self.paths = pickle.load(f)
        
    def Pickle(self, filename):
        #Node(0).fixEverything()
        with gzip.open(filename, "wb") as f:
            pickle.dump((self.nodes, self.trie, self.paths), f, -1)

    # doesn't work any more because of later optimizations
    #def Merge(self, filename):
    #    with gzip.open(filename, "rb") as f:
    #        newnodes, trie, paths = pickle.load(f)
    ##        trie.buildCache()
    #        paths.buildCache()
    #        mergednodes = {asn:self.nodes.setdefault(asn, Node(asn)) for asn in newnodes}
    #        for asn in sorted(mergednodes):
    #            mergednode = mergednodes[asn]
    #            newnode = newnodes[asn]
    #            trie.replace(newnode, mergednode)
    #            paths.replace(newnode, mergednode)
    #            for newdownstream in newnode.Cone:
    #                mergednode.addDownStream(mergednodes[newdownstream.ASN])
    #        self.trie.merge(trie)
    #        self.trie.clearCache()
    #        self.paths.merge(paths)
    #        self.paths.clearCache()
    #        Node(0).fixEverything()

    def Cone(self, ASN):
        node = self.nodes.get(int(ASN), None)
        if node:
            return node.getCone()
        return set()

    def Bake(self):
        Node(-1).fixEverything()
        for node in self.nodes.values():
            del node.upStream

class Node:
    current = None

    def __init__(self, ASN):
        self.ASN = int(ASN)
        self.upStream = set()
        self.Cone = {self}

    def addDownStream(self, Node):
        self.fixEverything()
        if Node in self.Cone:
            return
        Node.upStream.add(self)
        self.Cone.update(Node.Cone)
        for ds in Node.Cone:
            if ds == self:
                continue
            ds.upStream.add(self)
            ds.upStream.update(self.upStream)

    def fixEverything(self):
        if Node.current and Node.current != self:
            print("fixing", Node.current, "(!=", self, ")")
            for us in Node.current.upStream:
                if us == Node.current:
                    continue
                us.Cone.update(Node.current.Cone)
        Node.current = self

    def getCone(self):
        #self.fixUpStream()
        return self.Cone

    def __str__(self):
        return str(self.ASN)

    def __repr__(self):
        return self.__str__()




if __name__ == "__main__":
    """t = Tree()
    t.AddPair("7", "1")
    t.AddPair("6", "8")
    t.AddPair("8", "9")
    t.AddPair("9", "10")
    t.AddPair("10", "1")
    l = [str(x) for x in [1, 2, 3, 4, 5, 6, 7]]
    for as1 in l[:3]:
        for as2 in l:
            t.AddPair(as1, as2)
    for asn in sorted(t.nodes):
        print(str(asn), t.nodes[int(asn)].getCone())
    """

    # If we don't do this, the script may fail if the graph becomes too large
    sys.setrecursionlimit(1000000)
    try:
        CLI().cmdloop()
    except KeyboardInterrupt as i:
        print("but but but I wasn't done yet", file=sys.stderr)
l
