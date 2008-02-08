#!/usr/bin/env python

import dnet
import dpkt
import dsniff

class DHCPOS(dsniff.Handler):

    types = ('discover', 'offer', 'request', 'decline', 'ack', 'nak', 'release', 'inform')

    def setup(self):
        self.fpos = {}
        f = open('share/dhcpos_fingerprints.txt')
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            i = line.rfind(',')
            if self.fpos.has_key(line[:i]):
                print "duplicate", line[:i], line[i+1:]
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
            print '%s: %s (%s [%s] - %s):\n%s\n' % (self.types[map(ord, opts[dpkt.dhcp.DHCP_OPT_MSGTYPE])[0]-1],
                                   dnet.eth_ntoa(msg.chaddr),
                                   dnet.ip_ntoa(ip.src),
                                   opts.get(dpkt.dhcp.DHCP_OPT_HOSTNAME, 'unknown'),
                                   opts.get(dpkt.dhcp.DHCP_OPT_VENDOR_ID, 'unknown'),
                                   self.fpos.get(fp, 'UNKNOWN: %s' % fp))

if __name__ == '__main__':
    dsniff.main()
