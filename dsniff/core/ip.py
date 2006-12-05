# $Id$

import dpkt, pcap
import dsniff
from dsniff.lib import reasm

class IPHandler(dsniff.Handler):
    """IPv4/IPv6 handler, with basic IP fragment reassembly."""
    name = 'ip'
    max_frag_ids = 1000

    def setup(self):
        self.defrag = reasm.Defragger(self.max_frag_ids)

    def _register(self, event, callback):
        # XXX - pass through events (pcap filters) to pkt handler
        self.subscribe('pcap', event, self.recv_pkt)
        super(IPHandler, self)._register(event, callback)

    def _unregister(self, event, callback):
        self.unsubscribe('pcap', event, self.recv_pkt)
        super(IPHandler, self)._unregister(event, callback)

    def recv_pkt(self, pc, pkt):
        # Try to handle both IPv4 and IPv6...
        dlt = pc.datalink()
        if dlt == pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(pkt)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP and \
               eth.type != dpkt.ethernet.ETH_TYPE_IP6:
                return
            ip = eth.data
        elif dlt == pcap.DLT_LOOP or dlt == pcap.DLT_NULL:
            loop = dpkt.loopback.Loopback(pkt)
            if loop.family > 1500:  # XXX - see dpkt.loopback
                ip = loop.data.data
            else:
                ip = loop.data
        else:
            ip = dpkt.ip.IP(pkt[pc.dloff:])

        dsniff.Handler.ip = ip  # XXX

        if isinstance(ip, dpkt.ip.IP):
            if ip.off & 0x3fff: # IP_MF|IP_OFFMASK
                ip = self.defrag.defrag(ip)
                if ip:
                    self.publish(pc.event, ip)
            else:
                self.publish(pc.event, ip)
        elif isinstance(ip, dpkt.ip6.IP6):
            self.publish(pc.event, ip)
