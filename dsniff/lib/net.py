# $Id$

proto2num = {
    'ip':0, 'icmp':1, 'igmp':2, 'tcp':6, 'udp':17, 'ddp':37, 'ip6':46,
    'gre':47, 'esp':50, 'ah':51, 'icmp6':58, 'ospf':89, 'pim':103,
    'vrrp':112, 'isis':124
}
proto2name = dict(zip(proto2num.itervalues(), proto2num.iterkeys()))

# XXX - diverge from both IANA and nmap service names here
# XXX - multiple values can be returned as a list
serv2num = {
    'echo_reply':[(1,0),(58,129)], 'dst_unreach':[(1,3),(58,1)],
    'src_quench':(1,4), 'redirect':(1,5), 'echo':[(1,8),(58,128)],
    'time_exceeded':[(1,11),(58,3)], 'param_prob':[(1,12),(58,4)],

    'dns':(17,53), 'dhcp':[(17,67),(17,68)], 'tftp':(17,69),
    'krb5':[(17,88),(6,88)], 'portmap':(17,111), 'ntp':(17,123),
    'netbios-ns':(17,137), 'netbios-dgm':(17,138), 'snmp':(17,161),
    'slp':(17,427), 'ike':(17,500), 'syslog':(17,514), 'rip':(17,520),
    'hsrp':(17,1985), 'nfs':[(17,2049),(6,2049)],
    'rendezvous':(17,5353),

    'ftp':(6,21), 'ssh':(6,22), 'telnet':(6,23), 'smtp':[(6,25),(6,587)],
    'http':(6,80), 'pop':[(6,110), (6,109)], 'ident':(6,113), 'nntp':(6,119),
    'ms-rpc':[(6,135),(17,135),(6,1025)], 'netbios-ssn':[(6,139),(6,445)],
    'imap':(6,143), 'bgp':(6,179), 'fw-1':(6,256), 'ldap':[(6,389),(6,3268)],
    'https':(6,443), 'dantz':(6,497), 'rlogin':(6,513), 'rsh':(6,514),
    'lpr':(6,515), 'rtsp':(6,554), 'ipp':[(6,631),(17,631)],
    'ldap-ssl':(6,636), 'imap-ssl':(6,993), 'pop-ssl':(6,995),
    'socks':(6,1080), 'kazaa':(6,1214), 'citrix':(6,1494), 'oracle':(6,1521),
    'pptp':(6,1723), 'ms-winmedia':(6,1755), 'ms-msgs':(6,1863),
    'slsk':[(6,2234),(6,5534)], 'cvs':(6,2401),
    'http-proxy':[(6,3128),(6,8080)], 'mysql':(6,3306),
    'ms-term-serv':(6,3389), 'edonkey2000':(6,4662), 'upnp':(6,5000),
    'aim':(6,5190), 'yahoo':(6,5050), 'jabber':(6,5222),
    'postgres':(6,5432), 'gnutella':(6,6346), 'irc':(6,6667),
    'napster':(6,6699), 'bittorrent':(6,6881), 'icb':(6,7326),
    'jetdirect':(6,9100)
}
serv2name = {}

prog2num = {
    'portmapper': 100000, 'rstatd': 100001, 'rusersd': 100002,
    'nfs': 100003, 'ypserv': 100004, 'mountd': 100005, 'ypbind': 100007,
    'walld': 100008, 'yppasswdd': 100009, 'etherstatd': 100010,
    'rquotad': 100011, 'sprayd': 100012, '3270_mapper': 100013,
    'rje_mapper': 100014, 'selection_svc': 100015, 'database_svc': 100016,
    'rexd': 100017, 'alis': 100018, 'sched': 100019, 'llockmgr': 100020,
    'nlockmgr': 100021, 'x25.inr': 100022, 'statmon': 100023,
    'status': 100024, 'bootparamd': 100026, 'ypupdated': 100028,
    'keyserv': 100029, 'tfsd': 100037, 'nsed': 100038, 'nsemntd': 100039,
    'cmsd': 100068, 'ttdbserver': 100083, 'pcnfsd': 150001, 'amd': 300019,
    'netinfo': 200100000, 'netinfobind': 200100001,
    }
prog2name = dict(zip(prog2num.itervalues(), prog2num.iterkeys()))

def __init_serv2name():
    for value, key in serv2num.iteritems():
        if isinstance(key[0], int):
            serv2name[key] = value
        else:
            for k in key:
                serv2name[k] = value

__init_serv2name()

def proto_ntoa(proto, default=None):
    """Return name for given protocol number."""
    return proto2name.get(proto, default)

def proto_aton(proto, default=None):
    """Return number for given protocol name."""
    return proto2num.get(proto.lower(), default)

def serv_ntoa(proto, port, default=None):
    """Return service name for given (proto, port) tuple."""
    return serv2name.get((proto, port), default)

def serv_aton(serv, default=None):
    """Return (proto, port) tuple for given service name."""
    return serv2num.get(serv.lower(), default)

def rpcprog_ntoa(prog, default=None):
    """Return RPC program name for given program number."""
    return prog2name.get(prog, default)

def rpcprog_aton(prog, default=None):
    """Return RPC program number for given program name."""
    return prog2num.get(prog.lower(), default)

def proto_load(filename='/etc/protocols'):
    """Load internal table of IP protocols from a file."""
    f = open(filename)
    for line in f.readlines():
        if line[0] not in '# \t\r\n':
            l = line.split(None, 2)
            name = l[0].lower()
            proto = int(l[1])
            proto2name[proto] = name
            proto2num[name] = proto

def serv_load(filename='/etc/services'):
    """Load internal table of services from a file."""
    f = open(filename)
    for line in f.readlines():
        if line[0] not in '# \t\r\n':
            l = line.split(None, 2)
            name = l[0].lower()
            port, proto = l[1].split('/')
            serv = (proto_aton(proto), int(port))

            serv2name[serv] = name

            if name in serv2num:
                s = serv2num[name]
                if isinstance(s, list):
                    if serv not in s:
                        s.append(serv)
                else:
                    serv2num[name] = [ s, serv ]
            else:
                serv2num[name] = serv

if __name__ == '__main__':
    import unittest

    class netTestCase(unittest.TestCase):
        def test_proto_ntoa(self):
            self.failUnless(proto_ntoa(1) == 'icmp')
        def test_proto_aton(self):
            self.failUnless(proto_aton('icmp') == 1)
        def test_serv_ntoa(self):
            self.failUnless(serv_ntoa(6, 22) == 'ssh')
        def test_serv_aton(self):
            self.failUnless(serv_aton('ssh') == (6, 22))

    unittest.main()
