# $Id$

import glob, os, sys
import pcap, dnet
import dsniff

def lookupdev():
    """XXX - better pcap_lookupdev()"""
    intf = dnet.intf()
    ifent = intf.get_dst(dnet.addr('1.2.3.4')) or \
            [ x for x in intf if x['flags'] & dnet.INTF_FLAG_UP and
              x['type'] == dnet.INTF_TYPE_ETH ][0]
    return ifent['name']

class PcapFactory(object):
    def __new__(cls, *args, **kwargs):
        try:
            import wtap
            class Wtap(wtap.wtap): pass
            return Wtap(*args, **kwargs)
        except (ImportError, IOError):
            class Pcap(pcap.pcap): pass
            return Pcap(*args, **kwargs)

class PcapHandler(dsniff.Handler):
    """Packet capture handler."""
    name = 'pcap'

    interfaces = []
    snaplen = 31337
    prefilter = ''
    debug = 0

    def setup(self):
        if self.interfaces:
            l = []
            for i in self.interfaces:
                l.extend(glob.glob(i) or [ i ])
            self.interfaces = l
        elif not self.interfaces:
            self.interfaces = [ lookupdev() ]
        self.pcaps = {}

    def __pcap_open(self, name, **kwargs):
        def __recv_pkt(ts, pkt, pc):
            dsniff.Handler.ts = ts  # XXX
            dsniff.Handler.pkt = pkt
            dsniff.Handler.pc = pc
            self.publish(pc.event, pc, pkt)
        def __read_cb(pc, stat):
            if pc.dispatch(-1, __recv_pkt, pc) <= stat:
                self.abort()
            return True
        pc = PcapFactory(name, **kwargs)
        if not (os.path.isfile(pc.name) or pc.name == '-'):
            # FIXME - or only if b0rked BPF
            pc.setnonblock()
            self.timeout(0.1, __read_cb, pc, -1)
        else:
            dsniff.event.read(pc, __read_cb, pc, 0)
        return pc

    def __pcap_info(self, pc):
        if pc.filter:
            return '%s (%s, snaplen: %d)' % (pc.name, pc.filter, pc.snaplen)
        else:
            return '%s (snaplen: %d)' % (pc.name, pc.snaplen)

    def _register(self, event, callback):
        # Create new pcap handle as needed for new subscriptions
        pcfilter = ' and '.join(filter(None, [ self.prefilter, event ]))
        if None in self.pcaps:
            # XXX - reuse any cached pcaps
            self.pcaps[event] = self.pcaps.pop(None)
            for pc in self.pcaps[event]:
                pc.setfilter(pcfilter)
                pc.event = event
                if self.debug > 0:
                    print >>sys.stderr, 'updated', self.__pcap_info(pc)
        elif event not in self.pcaps:
            self.pcaps[event] = []
            for dev in self.interfaces:
                pc = self.__pcap_open(dev, timeout_ms=0,
                                      snaplen=self.snaplen)
                pc.setfilter(pcfilter)
                pc.event = event
                print >>sys.stderr, 'opened', self.__pcap_info(pc)
                self.pcaps[event].append(pc)
        super(PcapHandler, self)._register(event, callback)

    def _unregister(self, event, callback):
        super(PcapHandler, self)._unregister(event, callback)
        pcaps = self.pcaps.pop(event)
        if not self.callbacks:
            # XXX - cache last set of pcaps
            self.pcaps[None] = pcaps

    def teardown(self):
        for pcaps in self.pcaps.itervalues():
            for pc in pcaps:
                try:
                    stats = pc.stats()
                    print >>sys.stderr, \
                          'closed %s: %d packets received, %d dropped' % \
                          (self.__pcap_info(pc), stats[0], stats[1])
                except OSError:
                    print >>sys.stderr, 'closed', self.__pcap_info(pc)
