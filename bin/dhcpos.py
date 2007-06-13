#!/usr/bin/env python

import dnet
import dpkt
import dsniff

class DHCPOS(dsniff.Handler):

    def setup(self):
        self.fpos = {}
        f = open('share/dhcpos_fingerprints.txt')
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            i = line.rfind(',')
            self.fpos[line[:i]] = line[i+1:]
        f.close()
        self.subscribe('pcap', 'udp dst port 67', self.recv_pkt)

    def recv_pkt(self, pc, pkt):
        ip = dpkt.ethernet.Ethernet(pkt).ip
        msg = dpkt.dhcp.DHCP(ip.udp.data)
        opts = dict(msg.opts)
        if dpkt.dhcp.DHCP_OPT_PARAM_REQ in opts:
            l = map(ord, opts[dpkt.dhcp.DHCP_OPT_PARAM_REQ])
            fp = ','.join(map(str, l))
            print fp
            print '%s (%s): %s' % (dnet.eth_ntoa(msg.chaddr),
                                   dnet.ip_ntoa(ip.src),
                                   self.fpos.get(fp, 'UNKNOWN: %s' % fp))

if __name__ == '__main__':
    dsniff.main()
