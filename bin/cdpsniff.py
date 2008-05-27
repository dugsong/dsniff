#!/usr/bin/env python
#
# $Id$

import pprint
import dnet, dpkt
import dsniff
import sys

class CDPSniff(dsniff.Handler):
    name = 'cdpsniff'

    def setup(self):
        self.cache = {}
        self.subscribe('pcap', 'ether dst 01:00:0c:cc:cc:cc', self.recv_pkt)

    def teardown(self):
        print >>sys.stderr, 'caught %s unique cdp entries' % (len(self.cache), )

    def recv_pkt(self, pc, pkt):
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.src not in self.cache and eth.type == dpkt.ethernet.ETH_TYPE_CDP:
            d = dict([ (tlv.type, tlv.data) for tlv in eth.cdp.data ])
            self.cache[eth.src] = d
            print "%s [%s] - %s [%s]" % (d[1], dnet.eth_ntoa(eth.src), dnet.ip_ntoa(d[2][0].data), d[3])
            pprint.pprint(d)
            print

if __name__ == '__main__':
    dsniff.main()
