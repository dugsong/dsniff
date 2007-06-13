# $Id$

import traceback
import dnet, dpkt
import dsniff
from dsniff.lib import fcap, net, reasm

FLOW_START, FLOW_CLIENT_DATA, FLOW_SERVER_DATA, FLOW_END = range(4)

class FlowHalf(object):
    __slots__ = ('addr', 'port', 'pkts', 'bytes', 'data', 'save')

    def __init__(self, addr, pkts, bytes):
        self.addr = addr
        self.pkts = pkts
        self.bytes = bytes
        self.port = self.data = None
        self.save = {}

    def readlines(self, keepends=False): # XXX - need max buffer size
        """Return list of lines parsed from a flow data stream.
        """
        x = '_readlines_buf'
        self.save[x] = self.save.get(x, '') + self.data
        while self.save[x]:
            i = self.save[x].find('\n')
            if i < 0:
                break
            line, self.save[x] = self.save[x][:i+1], self.save[x][i+1:]
            if not keepends:
                line = line.rstrip()
            yield line

    def unpack(self, dpkt_cls, maxsz=1000 * 1000):
        """Iterator to return dpkt_cls instances parsed from a flow
        data stream.
        """
        x = dpkt_cls
        buf = self.save[x] = self.save.get(x, '') + self.data
        while buf:
            try:
                p = dpkt_cls(buf)
            except dpkt.UnpackError:
                break
            yield p
            buf = p.data
        # XXX - on decode error, maybe we should whack any saved buf?
        self.save[x] = buf[-maxsz:]
        raise StopIteration

class Flow(object):
    __slots__ = ('client', 'server', 'p', 'stime', 'etime',
                 'state', 'save', 'half', 'callbacks')
    _Half = FlowHalf

    def __init__(self, ts, ip):
        def _ip2addr(x):
            a = dnet.addr()
            if ip.v == 4: a.ip = x
            elif ip.v: a.ip6 = x
            return a
        self.client = self._Half(_ip2addr(ip.src), 1, ip.len)
        self.server = self._Half(_ip2addr(ip.dst), 0, 0)
        self.half = { ip.src:self.client, ip.dst:self.server }
        self.p = ip.p
        self.stime = self.etime = ts
        self.callbacks = []
        self.save = {}

    src = property(lambda self: self.client.addr)
    dst = property(lambda self: self.server.addr)
    sport = property(lambda self: self.client.port)
    dport = property(lambda self: self.server.port)

    def flip(self):
        self.client, self.server = self.server, self.client

    def register(self, callback):
        self.callbacks.append(callback)

    def unregister(self, callback):
        self.callbacks.remove(callback)

    def publish(self, state):
        self.state = state
        for cb in self.callbacks:
            try:
                cb(self)
            except:
                traceback.print_exc()

    def update(self, ts, ip):
        self.etime = ts
        half = self.half[ip.src]
        half.pkts += 1
        half.bytes += ip.len

    def __getitem__(self, k):
        try:
            return getattr(self, k)
        except AttributeError:
            raise KeyError

    def __repr__(self):
        return 'Flow(%(src)s, %(dst)s, %(p)s, %(sport)s, %(dport)s)' % self

    def __str__(self, arrow='>'):
        p = net.proto_ntoa(self.p)
        if self.dport is not None:
            if self.sport is None: # XXX - ICMP
                return '%s %s %s %s:%s' % (p, self.src, arrow, self.dst, self.dport)
            return '%s %s:%s %s %s:%s' % \
                   (p, self.src, self.sport, arrow, self.dst, self.dport)
        return '%s %s %s %s' % (p, self.src, arrow, self.dst)

class IpFlow(Flow):
    __slots__ = Flow.__slots__ + ('data',)

    def update(self, ts, ip):
        Flow.update(self, ts, ip)
        self.data = str(ip.data)

# XXX - to map reply to request type
_icmp_typemap = { 0:8, 10:9, 14:13, 16:15, 18:17, 34:33, 36:35, 38:37 }

class IcmpFlow(Flow):
    __slots__ = Flow.__slots__ + ('type', 'code')

    def __init__(self, ts, ip):
        Flow.__init__(self, ts, ip)
        t = ip.icmp.type
        if t in _icmp_typemap:
            self.flip()
            self.type = self.server.port = _icmp_typemap[t]
        else:
            self.type = self.server.port = t
        self.code = self.client.port = None

    def update(self, ts, ip):
        Flow.update(self, ts, ip)
        self.half[ip.src].data = str(ip.icmp.data)

class UdpFlow(Flow):
    def __init__(self, ts, ip):
        Flow.__init__(self, ts, ip)
        self.client.port = ip.udp.sport
        self.server.port = ip.udp.dport

    def update(self, ts, ip):
        Flow.update(self, ts, ip)
        self.half[ip.src].data = str(ip.udp.data)

class TcpHalf(FlowHalf):
    __slots__ = FlowHalf.__slots__ + ('flags', 'reasm')

class TcpFlow(Flow):
    _Half = TcpHalf

    def __init__(self, ts, ip):
        Flow.__init__(self, ts, ip)
        self.client.port = ip.tcp.sport
        self.server.port = ip.tcp.dport
        self.client.flags = ip.tcp.flags
        self.server.flags = 0
        self.client.reasm = self.server.reasm = None

    def update(self, ts, ip):
        Flow.update(self, ts, ip)
        half = self.half[ip.src]
        half.flags &= ip.tcp.flags
        # XXX - what about URG data?
        if half.reasm is None:
            is_syn = int(ip.tcp.flags & 0x02 == 0x02)
            half.reasm = reasm.Reassembler(ip.tcp.seq + is_syn, ip.tcp.win)
        if ip.tcp.data:
            half.data = half.reasm.reassemble(ip.tcp.seq, ip.tcp.data)

    def kill(self, rawsock):
        # XXX - should be FlowHalf method, abstracted to .inject()?
        # e.g. flow.client.kill(), flow.client.send('foo')
        if self.server.reasm is None:
            return -1
        if self.src.type == dnet.ADDR_TYPE_IP:
            ip = dpkt.ip.IP(src=self.src.ip, dst=self.dst.ip, p=self.p)
            tcp = dpkt.tcp.TCP(sport=self.dport, dport=self.sport,
                               seq=self.server.reasm.cur,
                               flags=dnet.TH_RST)
            ip.data = tcp
            ip.len += len(tcp)

            for i in range(3):
                ip.id = id(ip)
                tcp.seq += i * tcp.win
                ip.sum = tcp.sum = 0
                rawsock.send(str(ip))
            return 0
        else: # XXX - TODO IPv6
            return -1

class FlowHandler(dsniff.Handler):
    """IPv4/IPv6 flow handler, with basic TCP/IP reassembly
    and GRE, IPv6-in-IPv4, and IP-IP decapsulation.
    XXX - should we decapsulate SOCKS also? or does a SocksHandler
    publish new IP events?
    """
    name = 'flow'
    max_flows = 5000
    flowcls = { 1:IcmpFlow, 6:TcpFlow, 17:UdpFlow }

    def setup(self):
        def __lru_flows(cache):
            l = [ (v.etime, k) for k, v in cache.iteritems() ]
            l.sort()
            for ts, k in l[:cache.maxsz / 8]:
                cache.pop(k).publish(FLOW_END)
        self.cache = reasm.Cache(self.max_flows, reclaimfn=__lru_flows)
        self.fcap = fcap.Fcap()
        self.pcap_filter = None

    def teardown(self):
        self.cache.clear()

    def __resubscribe(self):
        s = self.fcap.pcap_filter()
        if self.pcap_filter != s:
            if self.pcap_filter:
                self.unsubscribe('ip', self.pcap_filter, self.recv_ip)
            self.pcap_filter = s
            self.subscribe('ip', self.pcap_filter, self.recv_ip)

    def _register(self, event, callback):
        self.fcap.add(event, event)
        self.__resubscribe()
        super(FlowHandler, self)._register(event, callback)

    def _unregister(self, event, callback):
        self.fcap.delete(event, event)
        self.__resubscribe()
        super(FlowHandler, self)._unregister(event, callback)
        # XXX - should whack cached flow callback

    def _hash_tuple(self, ip):
        # XXX - ugly but fast... er
        t = ip.data
        if ip.p == 6 or ip.p == 17:
            if ip.src > ip.dst:
                return (ip.dst, ip.src, ip.p, t.dport, t.sport)
            return (ip.src, ip.dst, ip.p, t.sport, t.dport)
        if ip.p == 1:
            if ip.src > ip.dst:
                return (ip.dst, ip.src, _icmp_typemap.get(t.type, t.type))
            return (ip.src, ip.dst, _icmp_typemap.get(t.type, t.type))
        if ip.src > ip.dst:
            return (ip.dst, ip.src, ip.p)
        return (ip.src, ip.dst, ip.p)

    def _set_direction(self, flow, ip):
        t = ip.data
        if (ip.p == 6 and t.flags & 0x12 == 0x12) or \
           (flow.sport is not None and flow.sport != flow.dport and
            flow.sport in self.fcap.matcher.dport):
            flow.flip()

    def recv_ip(self, ip):
        if ip.v == 6:   # XXX - fake the funk
            ip.p = ip.nxt
            ip.len = 40 + ip.plen

        # XXX - decapsulate tunnel protocols
        if ip.p == 47: # GRE
            if ip.gre.p == 0x800: # ETH_TYPE_IP
                return self.recv_ip(ip.gre.ip)
            elif ip.gre.p == 0x880B and ip.gre.ppp.p == 0x21:
                return self.recv_ip(ip.gre.ppp.ip)
        elif ip.p == 41: # IPv6-in-IPv4
            return self.recv_ip(ip.ip6)
        elif ip.p == 4: # IPIP
            return self.recv_ip(ip.ip)

        t = self._hash_tuple(ip)
        if t in self.cache:
            flow = self.cache[t]
        else:
            flow = self.cache[t] = self.flowcls.get(ip.p, IpFlow)(self.ts, ip)
            self._set_direction(flow, ip)
            # XXX - cache currently registered matching callbacks in flow
            for e in self.fcap.match(src=flow.src, dst=flow.dst, p=flow.p,
                                     sport=flow.sport, dport=flow.dport):
                for cb in self.callbacks[e]:
                    flow.register(cb)
            flow.publish(FLOW_START)

        dsniff.Handler.flow = flow  # XXX
        flow.update(self.ts, ip)

        if flow.client.data:
            flow.publish(FLOW_CLIENT_DATA)
            flow.client.data = None
        elif flow.server.data:
            flow.publish(FLOW_SERVER_DATA)
            flow.server.data = None
