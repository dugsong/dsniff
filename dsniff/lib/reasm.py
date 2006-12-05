# $Id$

"""Reassembly helpers.
XXX - only implements 'BSD' algorithm
"""

import copy, heapq

class Cache(dict):
    """Fixed-size dict.

    Arguments:
    maxsz     -- maximum number of entries

    Keyword arguments:
    reclaimfn -- callback to be executed on cache fill, to clear
                 at least one entry.
    """
    def __init__(self, maxsz,
                 reclaimfn=lambda d: d.popitem()):
        self.maxsz = maxsz
        self._reclaimfn = reclaimfn

    def __setitem__(self, k, v):
        if self.__len__() >= self.maxsz:
            self._reclaimfn(self)
        dict.__setitem__(self, k, v)

    def clear(self):
        while self.__len__() > 0:
            self._reclaimfn(self)

class Reassembler(object):
    """Quick-n-dirty TCP stream reassembler.
    """
    def __init__(self, isn=0, win=0):
        self.cur = isn
        self.win = win
        self.q = [] # heapq of (seq, buf)

    def reassemble(self, seq, buf):
        """Given a sequence number and buffer, return sequenced data.
        XXX - half-duplex, doesn't require ACK of reassembled data
        XXX - need to limit buffering, implement windowing, sequence healing
        """
        # XXX - fastpath properly sequenced data.
        if seq == self.cur and not self.q:
            self.cur += len(buf)
            return buf
        # XXX - favor newer data
        heapq.heappush(self.q, (seq, buf))
        l = []
        while self.q:
            if self.q[0][0] <= self.cur:
                seq, buf = heapq.heappop(self.q)
                if seq != self.cur:
                    # Reverse overlap. Trim left (empty string on rexmit)...
                    buf = buf[self.cur-seq:]
                l.append(buf)
                self.cur += len(buf)
            else:
                break
        return ''.join(l)

class Defragger(object):
    """Quick-n-dirty IP fragment reassembler.
    """
    def __init__(self, maxfragids=1000):
        self.pkts = Cache(maxfragids)

    def defrag(self, ip):
        """Given an IP fragment, try to return the reassembled packet."""
        t = (ip.src, ip.dst, ip.p, ip.id)
        try:
            ipq = self.pkts[t]
        except KeyError:
            ipq = self.pkts[t] = Reassembler()
            ipq.totlen = 0
            ipq.bufs = []

        off = (ip.off & 0x1fff) << 3    # IP_OFFMASK
        buf = ipq.reassemble(off, str(ip.data))
        if buf:
            ipq.bufs.append(buf)

        if ipq.totlen == 0:
            # Check for last frag.
            if ip.off & 0x2000 == 0:    # IP_MF
                ipq.totlen = off + len(ip.data)

        if ipq.totlen != 0 and sum(map(len, ipq.bufs)) == ipq.totlen:
            ip2 = copy.copy(ip)
            ip2.off = ip2.sum = 0
            ip2.data = ''.join(ipq.bufs)
            ip2.len = ipq.totlen
            ip2.unpack(str(ip2))
            del self.pkts[t]
            return ip2

if __name__ == '__main__':
    import unittest

    class ReasmTest(unittest.TestCase):
        def test_reasm(self):
            # Shankar and Paxson "Active Mapping" test, pinched from fragtest
            icmpecho = 'tcssidsq'
            off_data = (
                (0,  icmpecho + '1'*3*8),
                (40, '2'*2*8),
                (56, '3'*3*8),
                (16, '4'*4*8),
                (56, '5'*3*8),
                (80, '6'*3*8)
                )
            data_policy = {
                '1'*3*8 + '4'*2*8 + '2'*8 + '3'*3*8 + '6'*3*8 : 'BSD',
                '1'*8 + '4'*3*8 + '2'*2*8 + '5'*3*8 + '6'*3*8 : 'BSD-right',
                '1'*3*8 + '4'*2*8 + '2'*8 + '5'*3*8 + '6'*3*8 : 'Linux',
                '1'*3*8 + '4'*8 + '2'*2*8 + '3'*3*8 + '6'*3*8 : 'First',
                '1'*8 + '4'*4*8 + '2'*8 + '5'*3*8 + '6'*3*8 : 'Last',
                }
            asm = Reassembler()
            l = []
            for off, data in off_data:
                s = asm.reassemble(off, data)
                if s:
                    l.append(s)
            s = ''.join(l)[len(icmpecho):]
            assert data_policy[s] == 'BSD'

    unittest.main()
