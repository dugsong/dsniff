# $Id$

"""XXX quick pcap-like flow specification language
should use something like RuleDispatch instead...
"""

try:
    from __builtin__ import set
except ImportError:
    from sets import Set as set
import dnet
import itree, net
from pyparsing import *

class Matcher(object):
    """Flow matcher.

    Flow tuple keyword arguments:

    src   -- source address as dnet.addr object
    dst   -- destination address as dnet.addr object
    p     -- IP protocol as integer
    sport -- source port (or ICMP code) as integer
    dport -- destination port (or ICMP type) as integer
    """
    __keys = ('p', 'sport', 'dport')

    def __init__(self):
        self.src, self.src_any = itree.Itree(), set()
        self.dst, self.dst_any = itree.Itree(), set()
        for k in self.__keys:
            setattr(self, k, { None: set() })

    def add(self, item, **ftuple):
        """Add an item to be matched on a flow tuple filter.
        Flow tuple values may be lists.
        """
        if 'src' in ftuple:
            value = ftuple['src']
            # XXX - handle lists of values
            if not isinstance(value, list):
                value = [ value ]
            for v in value:
                self.src.add(v.net(), v.bcast(), item)
        else:
            self.src_any.add(item)

        if 'dst' in ftuple:
            value = ftuple['dst']
            # XXX - handle lists of values
            if not isinstance(value, list):
                value = [ value ]
            for v in value:
                self.dst.add(v.net(), v.bcast(), item)
        else:
            self.dst_any.add(item)

        for k in self.__keys:
            d = getattr(self, k)
            value = ftuple.get(k, None)
            # XXX - handle lists of values
            if not isinstance(value, list):
                value = [ value ]
            for v in value:
                if v not in d:
                    d[v] = set()
                d[v].add(item)

    def match(self, **ftuple):
        """Return a list of matched items for the specified flow tuple."""
        items = []
        items.append(self.src_any.union(self.src.match(ftuple.get('src', None))))
        items.append(self.dst_any.union(self.dst.match(ftuple.get('dst', None))))
        for k in self.__keys:
            d = getattr(self, k)
            items.append(d[None].union(d.get(ftuple.get(k, None), ())))
        items = list(reduce(lambda x, y: x.intersection(y), items))
        items.sort()
        return items

class Parser(object):
    """XXX - crappy pcap-subset flow filter parser."""
    def __init__(self):
        self.__fcap_items = {}
        self.__parsed = {}

        _set_src = lambda s, l, t: self._set_addr('src', t[:])
        _set_dst = lambda s, l, t: self._set_addr('dst', t[:])
        _set_p = lambda s, l, t: self._set_proto('p', t[:])
        _set_sport = lambda s, l, t: self._set_port('sport', t[:])
        _set_dport = lambda s, l, t: self._set_port('dport', t[:])

        INT = Word(nums)
        IPNAME = Combine(Word(alphanums) + ZeroOrMore('.' + Word(alphanums)))
        IPCIDR = Combine(IPNAME + '/' + INT)

        HOST = Optional(Suppress('host')) + IPNAME + \
               ZeroOrMore(Suppress('or') + IPNAME)
        NET = Suppress('net') + IPCIDR + ZeroOrMore(Suppress('or') + IPCIDR)
        ADDR = NET | HOST
        WKP = oneOf("icmp tcp udp")

        SRCADDR = Suppress('src') + ADDR
        DSTADDR = Suppress('dst') + ADDR

        PROTO = WKP | (Optional(Suppress('ip')) + Suppress('proto') + INT)
        PROTOS = PROTO + ZeroOrMore(Suppress('or') + PROTO)

        PORTS = Suppress('port') + Word(alphanums) + \
                ZeroOrMore(Suppress('or') + Word(alphanums))
        SRCPORT = Suppress('src') + PORTS
        DSTPORT = Suppress('dst') + PORTS

        # only allow one src predicate, but src predicate can be a list
        # maybe allow a src predicate to be recursive also
        PRED = SRCPORT.setParseAction(_set_sport) | \
               DSTPORT.setParseAction(_set_dport) | \
               SRCADDR.setParseAction(_set_src) | \
               DSTADDR.setParseAction(_set_dst) | \
               PROTOS.setParseAction(_set_p)

        EXPR = PRED + ZeroOrMore(Suppress('and') + PRED) + \
               restOfLine.setParseAction(self._error)

        self.parser = EXPR

    def _set_addr(self, k, v):
        if k in self.__parsed:
            raise ValueError, '%s already set' % k
        self.__parsed[k] = map(dnet.addr, v)

    def _set_proto(self, k, v):
        if k in self.__parsed:
            raise ValueError, '%s already set' % k
        def _parse_proto(p):
            n = net.proto_aton(p)
            if not n:
                n = int(p.split()[-1])
            return n
        self.__parsed[k] = map(_parse_proto, v)

    def _set_port(self, k, v):
        if k in self.__parsed:
            raise ValueError, '%s already set' % k
        def _parse_port(p):
            t = net.serv_aton(p)
            if t:
                n = t[-1]
            else:
                n = int(p)
            return n
        self.__parsed[k] = map(_parse_port, v)

    def _error(self, s, l, t):
        if t[0]:
            raise SyntaxError, 'invalid input at char %d: %r' % (l, t[0])

    def parse(self, s):
        """Parse filter string into dict."""
        self.__parsed = {}
        if s:
            self.parser.parseString(s)
        return self.__parsed

class Fcap(object):
    def __init__(self):
        self.parser = Parser()
        self.matcher = Matcher()
        self.__fcap_items = {}
        self.__fcap_parsed = {}

    def add(self, fcap, item):
        """Add item to return on flow filter match."""
        d = self.parser.parse(fcap)
        # Save raw filter and item
        if fcap not in self.__fcap_items:
            self.__fcap_items[fcap] = []
            self.__fcap_parsed[fcap] = d
        self.__fcap_items[fcap].append(item)
        # Add filter to DAG
        self.matcher.add(item, **d)

    def delete(self, fcap, item):
        """Delete flow filter match of item."""
        self.__fcap_items[fcap].remove(item)
        if not self.__fcap_items[fcap]:
            del self.__fcap_items[fcap], self.__fcap_parsed[fcap]
        # XXX - recompile DAG
        self.matcher = Matcher()
        for fcap, items in self.__fcap_items.iteritems():
            d = self.__fcap_parsed[fcap]
            for item in items:
                self.matcher.add(item, **d)

    def match(self, **ftuple):
        return self.matcher.match(**ftuple)

    def pcap_filter(self):
        """Return pcap filter expression from compiled flow filter."""
        # XXX - gross hack to get around BPF_MAXINSNS limit on BSD for
        # programs like authsnarf.  if only the BPF optimizer (or i)
        # were a little smarter...
        fields = { 'proto':[], 'tcp port':[], 'udp port':[] }
        l = []
        for fcap, d in self.__fcap_parsed.iteritems():
            if d.keys() == ['dport', 'p']:
                if d['p'] == [6]:
                    fields['tcp port'].extend(d['dport'])
                elif d['p'] == [17]:
                    fields['udp port'].extend(d['dport'])
                else:
                    raise ValueError
            elif d.keys() == ['p']:
                fields['proto'].extend(d['p'])
            elif fcap:
                l.append('(%s)' % fcap.replace('src ', '').replace('dst ', ''))
        for k, v in fields.iteritems():
            if v:
                v.sort()
                l.append('(%s %s)' % (k, ' or '.join(map(str, v))))
        l.sort()
        return ' or '.join(l)

if __name__ == '__main__':
    import unittest

    class TestParser(unittest.TestCase):
        def test_parse(self):
            tests = {
                'tcp':{ 'p':[6] },
                'tcp or udp':{ 'p':[6,17] },
                'tcp and dst port 80':{ 'p':[6], 'dport':[80] },
                'tcp and dst port 22 or 80':{ 'p':[6], 'dport':[22,80] },
                'dst 1.2.3.4 and tcp and dst port 22':
                { 'p':[6], 'dst':[dnet.addr('1.2.3.4')], 'dport':[22] },
                'dst net 5.6.7.0/24 or 1.2.3.0/24 and tcp and src port 80 or 81':
                { 'p':[6], 'sport':[80,81],
                  'dst':[dnet.addr('5.6.7.0/24'), dnet.addr('1.2.3.0/24')] },
                }

            parser = Parser()
            for k, v in tests.iteritems():
                d = parser.parse(k)
                assert d == v, 'expected %r, got %r' % (v, d)

    class TestMatcher(unittest.TestCase):
        def test_match(self):
            matcher = Matcher()
            matcher.add('ping', p=1, dport=8)
            matcher.add('ssh', p=6, dport=22)
            matcher.add('tcp', p=6)
            matcher.add('http', p=6, dport=80)
            matcher.add('dns', p=17, dport=53)
            matcher.add('gre', p=47)
            matcher.add('intranet', dst=dnet.addr('10.0.0.0/8'))
            matcher.add('testbed', dst=dnet.addr('10.0.5.0/24'))
            assert matcher.match(p=6, dport=22) == ['ssh', 'tcp']
            assert matcher.match(dst=dnet.addr('10.1.2.3'),
                                 p=17, dport=53) == ['dns', 'intranet']
            assert matcher.match(dst=dnet.addr('10.0.5.0'), p=6, dport=23) == [ 'intranet', 'tcp', 'testbed' ]
            assert matcher.match(dst=dnet.addr('1.2.3.4'), p=17, dport=80) == []
            assert matcher.match(p=6, dport=80) == ['http', 'tcp']
            assert matcher.match(p=6, dport=666) == ['tcp']
            assert matcher.match(p=50) == []
            assert matcher.match(p=1, dport=8) == ['ping']
            assert matcher.match(p=1, dport=0) == []

    class TestFcap(unittest.TestCase):
        def test_fcap(self):
            fcap = Fcap()
            fcap.add('tcp and dst port 22', 'ssh')
            fcap.add('tcp and dst port 80', 'http')
            assert fcap.match(src=1, dst=2, p=6, dport=22) == ['ssh']
            assert fcap.match(src=1, dst=2, p=17, dport=22) == []
            assert fcap.pcap_filter() == '(tcp port 22 or 80)'
            fcap.delete('tcp and dst port 22', 'ssh')
            assert fcap.match(src=1, dst=2, p=6, dport=22) == []
            assert fcap.pcap_filter() == '(tcp port 80)'
            fcap.add('tcp and dst port 80 and dst net 216.239.32.0/19 or 72.14.192.0/19', 'GOGL')
            assert fcap.match(dst=dnet.addr('72.14.192.123'), p=6, dport=80) == [ 'GOGL', 'http' ]

    unittest.main()
