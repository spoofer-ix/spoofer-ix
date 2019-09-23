#!/usr/bin/env python3

class Trie:
    """maps the IPv4 address space to a trie structure by storing 32 bit unsigned integers"""
    def __init__(self):
        self.values = set()
        self.links = [None, None]
        self.valuecache = (set(), set())

    def __addInt(self, Int, prefixLen, value, div=(1 << 31)):
        """ recursively stores "value" for the given integer in the trie, modulo prefix length """
        if not prefixLen:
            # terminate recursion, don't care about the less significant bits, store value directly
            self.values.add(value)
            return self
        # bit is 0 or 1, rest is the reminder after dividing by div
        # 8bit example: Int is 255, div is 128
        # result would be : bit is 1, rest is 127
        # recursively fill right subtree (links[bit]) with rest(=127), using div>>1(=64)
        bit, rest = divmod(Int, div)
        if not self.links[bit]:
            self.links[bit] = Trie()
        return self.links[bit].__addInt(rest, prefixLen-1, value, div >> 1)

    def __addIntValues(self, Int, prefixLen, values, div=(1 << 31)):
        """ recursively stores "values" for the given integer in the trie, modulo prefix length """
        if not prefixLen:
            # terminate recursion, don't care about the less significant bits, store value directly
            self.values.update(values)
            return self
        # bit is 0 or 1, rest is the reminder after dividing by div
        # 8bit example: Int is 255, div is 128
        # result would be : bit is 1, rest is 127
        # recursively fill right subtree (links[bit]) with rest(=127), using div>>1(=64)
        bit, rest = divmod(Int, div)
        if not self.links[bit]:
            self.links[bit] = Trie()
        return self.links[bit].__addIntValues(rest, prefixLen-1, values, div >> 1)


    def __lookUp(self, Int, div=(1 << 31)):
        "recursively return union of all values stored below given Int"
        bit, rest = divmod(Int, div)
        if not self.links[bit]:
            return self.values
        return self.values.union(self.links[bit].__lookUp(rest, div >> 1))


    def merge(self, trie):
        """recursively merge with given trie"""
        if trie:
            self.values.update(trie.values)
            if self.links[0]:
                self.links[0].merge(trie.links[0])
            else:
                self.links[0] = trie.links[0]
            if self.links[1]:
                self.links[1].merge(trie.links[1])
            else:
                self.links[1] = trie.links[1]
                
    def replace(self, old, new):
        if old in self.values:
            self.values.remove(old)
            self.values.add(new)
        for link, cache in zip(self.links, self.valuecache):
            if old in cache:
                link.replace(old, new)
                
    @staticmethod
    def ipstr2int(ipstr):
        """helper method to convert given ip string to integer representation"""
        intip = 0
        for octet in map(int, ipstr.split(".")):
            intip <<= 8
            intip += octet
        return intip
    
    @classmethod
    def subnet2ints(cls, subnetstr):
        """helper method to convert ipv4 subnet string in the form of "10.0.0.1/24" to integer representation plus subnet int"""
        ipstr, net = subnetstr.split("/")
        net = int(net)
        # build subnet bitmask from net
        mask = ((1<<net) - 1) << 32-net
        # bitwise AND over integer representation of IP and mask
        return cls.ipstr2int(ipstr) & mask, net

    @staticmethod
    def intip2ipstr(intip):
        """helper method to convert integer representation of IP back to IP string"""
        div = 1 << 24
        octets = []
        while div:
            octet, intip = divmod(intip, div)
            octets.append(str(octet))
            div >>= 8
        return ".".join(octets)

    def addSubnet(self, subnetstr, value):
        intip, net = self.subnet2ints(subnetstr)
        return self.__addInt(intip, net, value)

    def addSubnetValues(self, subnetstr, values):
        intip, net = self.subnet2ints(subnetstr)
        return self.__addIntValues(intip, net, values)


    def lookUpIP(self, IP):
        return self.__lookUp(self.ipstr2int(IP))

    """def listall(self, intip=0, depth=0):

        if self.values:
            print(self.intip2ipstr(intip << (32-depth)) + "/" + str(depth), self.values)
        if self.links[0]:
            self.links[0].listall((intip << 1), depth+1)
        if self.links[1]:
            self.links[1].listall((intip << 1) + 1, depth + 1)
    """

    def uniqueIPs(self, ASN, depth=32):
        """return number of unique IPs stored in trie, filtered by origin ASN ("value"). Requires value cache to be built"""
        count = 0
        # our remaining depth in the tree directly reflects how many nodes (i.e., IPs) are covered below us
        # i.e., a /24 subnet translates to a "remaining depth" of 32-24=8, encoding 1<<8=256 "values"  
        if ASN in self.values:
            return 1 << depth
        if ASN in self.valuecache[0]:
            count += self.links[0].uniqueIPs(ASN, depth-1)
        if ASN in self.valuecache[1]:
            count += self.links[1].uniqueIPs(ASN, depth-1)
        return count
    

    def _prefixValues(self, net=0):
        if self.values:
            yield(0, net, self.values)
        if self.links[0]:
            for i, n, v in self.links[0]._prefixValues(net+1):
                yield i, n, v
        if self.links[1]:
            for i, n, v in self.links[1]._prefixValues(net+1):
                yield (1<<(31-net)) + i, n, v


    def lines(self):
        """line iterator over contents of trie"""
        for i, n, v in self._prefixValues():
            yield self.intip2ipstr(i)+"/"+str(n) + " " + ",".join([str(node) for node in v])
    
    def buildCache(self):
        """recursively traverse the trie to build a lookup cache to be used by "uniqueIPs" """
        if self.links[0]:
            self.valuecache[0].update(self.links[0].buildCache())
        if self.links[1]:
            self.valuecache[1].update(self.links[1].buildCache())
        return self.values.union(self.valuecache[0], self.valuecache[1])
        
    def clearCache(self):
        for link, cache in zip(self.links, self.valuecache):
            if cache:
                link.clearCache()
        self.valuecache=(set(), set())
            
    

if __name__ == "__main__":
    t = Trie()
    t.addSubnet("10.23.42.1/24", "AS4711")
    t.addSubnet("10.23.42.1/16", "AS1337")
    t.addSubnet("10.23.23.250/24", "AS2337")
    print(t.lookUpIP("10.23.42.73"))
    t.buildCache()
    print(t.uniqueIPs("AS4711"), "unique IPs encoded in trie for AS4711")
    print(t.uniqueIPs("AS1337"), "unique IPs encoded in trie for AS1337")
    #t.listall()

