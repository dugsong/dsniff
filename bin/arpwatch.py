#!/usr/bin/env python

# $Id$

import cPickle, sys
import dnet, dpkt
import dsniff

class ArpWatch(dsniff.Handler):
    name = 'arpwatch'
    filename = False

    def setup(self):
        try:
            self.cache = cPickle.load(open(self.filename))
            print >>sys.stderr, 'loaded %s entries from %s' % (len(self.cache), self.filename)
        except IOError:
            self.cache = {}
        self.subscribe('pcap', 'arp[6:2] = 2', self.recv_pkt)

    def teardown(self):
        cPickle.dump(self.cache, open(self.filename, 'wb'))
        print >>sys.stderr, 'saved %s entries to %s' % (len(self.cache), self.filename)

    def recv_pkt(self, pc, pkt):
        arp = dpkt.ethernet.Ethernet(pkt).arp
        try:
            old = self.cache[arp.spa]
            if old != arp.sha:
                self.cache[arp.spa] = arp.sha
                print 'CHANGE: %s is-at %s (was-at %s)' % \
                      (dnet.ip_ntoa(arp.spa), dnet.eth_ntoa(arp.sha),
                       dnet.eth_ntoa(old))
        except KeyError:
            self.cache[arp.spa] = arp.sha
            print 'NEW: %s is-at %s' % (dnet.ip_ntoa(arp.spa),
                                  dnet.eth_ntoa(arp.sha))

if __name__ == '__main__':
    dsniff.add_option('-f', dest='arpwatch.filename',
                            default='/var/run/arpwatch.pkl',
                            help='cache file')
    dsniff.main()
