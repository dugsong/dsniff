#!/usr/bin/env python

"""
port of Michal Zalewski's p0fv2 passive OS fingerprinting tool
"""

# $Id$

# based on p0f-2.0.6b1
# signatures brought in from 2.0.8

# XXX - TODO: RST fingerprinting, masquerade/NAT detection, diagnostics

import struct, time
import dpkt

PACKET_BIG = 100

MOD_NONE   = 0
MOD_CONST  = 1
MOD_MSS    = 2
MOD_MTU    = 3

wss2mod = {
    '*':(MOD_CONST, lambda x: 1),
    's':(MOD_MSS, lambda x: int(x[1:])),
    't':(MOD_MTU, lambda x: int(x[1:])),
    '%':(MOD_CONST, lambda x: int(x[1:]))
}

qbits = [0] + [2**n for n in range(13)]
qflags = ['.', 'P', 'Z', 'I', 'U', 'X', 'A', 'T', 'F', 'D', '!', 'K', 'Q', '0']

quirk2bits = dict(zip(qflags, qbits))
quirk2flags = dict(zip(qbits, qflags))

genre2name = {
    '-':'userland',
    '*':'no_detail',
    '@':'generic'
}

mtu2link = {
    40:"unspecified",       # XXX
    256:"radio modem",
    386:"ethernut",
    552:"SLIP line / encap ppp",
    576:"sometimes modem",
    1280:"gif tunnel",
    1300:"PIX:SMC:sometimes wireless",
    1362:"sometimes DSL (1)",
    1372:"cable modem",
    1400:"(Google/AOL)",    # To be investigated
    1415:"sometimes wireless",
    1420:"GPRS:T1:FreeS/WAN",
    1423:"sometimes cable",
    1440:"sometimes DSL (2)",
    1442:"IPIP tunnel",
    1450:"vtun",
    1452:"sometimes DSL (3)",
    1454:"sometimes DSL (4)",
    1456:"ISDN ppp",
    1458:"BT DSL (?)",
    1462:"sometimes DSL (5)",
    1476:"IPSec/GRE",
    1480:"IPv6/IPIP",
    1492:"pppoe (DSL)",
    1496:"vLAN",
    1500:"ethernet/modem",
    1656:"Ericsson HIS",
    2024:"wireless/IrDA",
    2048:"Cyclom X.25 WAN",
    2250:"AiroNet wireless",
    3924:"loopback",
    4056:"token ring (1)",
    4096:"Sangoma X.25 WAN",
    4352:"FDDI",
    4500:"token ring (2)",
    9180:"FORE ATM",
    16384:"sometimes loopback (1)",
    16436:"sometimes loopback (2)",
    18000:"token ring x4"
}

def string_to_sig(line, ln=0):
    """Convert printable fingerprint entry string to a sig dict."""
    try:
        w, t, d, s, obuf, quirks, genre, desc = line.split(':')
        t = int(t)
        d = int(d)
        if s[0] != '*':
            s = int(s)
        else:
            s = 0
    except ValueError:
        raise 'Syntax error in config line %d' % ln

    sig = { 'mss_mod':MOD_NONE, 'mss':0 }

    while genre:
        g = genre[0]
        try:
            sig[genre2name[genre[0]]] = 1
            genre = genre[1:]
        except KeyError:
            break
    if not genre:
        raise 'Empty OS genre in line %d' % ln

    sig['os'] = genre
    sig['desc'] = desc
    sig['ttl'] = t
    sig['tot'] = s
    sig['df'] = d

    wss = w[0].lower()
    try:
        mod = wss2mod[wss]
        sig['wss_mod'], sig['wss'] = mod[0], mod[1](w)
    except KeyError:
        sig['wss_mod'], sig['wss'] = MOD_NONE, int(w)
    except:
        raise 'Bad %snn value in WSS in line %d' % (wss, ln)

    sig['wsc_mod'] = MOD_NONE
    sig['wsc'] = 0
    sig['zero_stamp'] = 1

    sig['opts'] = []
    opts = obuf.split(',')
    for opt in opts:
        o = opt[0].lower()
        if o == '.':
            break
        elif o == 'n':
            sig['opts'].append(dpkt.tcp.TCP_OPT_NOP)
        elif o == 'e':
            sig['opts'].append(dpkt.tcp.TCP_OPT_EOL)
            # XXX check for end
        elif o == 's':
            sig['opts'].append(dpkt.tcp.TCP_OPT_SACKOK)
        elif o == 't':
            sig['opts'].append(dpkt.tcp.TCP_OPT_TIMESTAMP)
            if not opt[1:]:
                sig['zero_stamp'] = 0
        elif o == 'w':
            sig['opts'].append(dpkt.tcp.TCP_OPT_WSCALE)
            if opt[1] == '*':
                sig['wsc_mod'], sig['wsc'] = MOD_CONST, 1
            elif opt[1] == '%':
                try: sig['wsc_mod'], sig['wsc'] = MOD_CONST, int(opt[2:])
                except: raise 'Null modulo for wscale in line %d' % ln
            else:
                try: sig['wsc_mod'], sig['wsc'] = MOD_NONE, int(opt[1:])
                except: raise 'Incorrect W value in line %d' % ln
        elif o == 'm':
            sig['opts'].append(dpkt.tcp.TCP_OPT_MSS)
            if opt[1] == '*':
                sig['mss_mod'], sig['mss'] = MOD_CONST, 1
            elif opt[1] == '%':
                try: sig['mss_mod'], sig['mss'] = MOD_CONST, int(opt[2:])
                except: raise 'Null modulo for MSS in config line %d' % ln
            else:
                try: sig['mss_mod'], sig['mss'] = MOD_NONE, int(opt[1:])
                except: raise 'Incorrect M value in line %d' % ln
        elif o == '?':
            try: sig['opts'].append(int(opt[1:]))
            except: raise 'Bogus ?nn value in line %d' % ln
        else:
            raise 'Unknown TCP option %s in line %d' % (o, ln)

    sig['quirks'] = 0
    for c in quirks:
        if c == '.': break
        try: sig['quirks'] |= quirk2bits[c]
        except KeyError: raise 'Bad quirk %s in line %d' % (c, ln)

    return sig

def load_config(f):
    """Load fingerprint entries from a file, and return them in a
    fingerprint dict.

    Arguments:

    f -- p0f2 fingerprint file handle
    """
    bh = {}
    ln = 0
    for line in f.readlines():
        ln += 1
        # Skip comments and empty lines
        line = line.strip()
        if line and line[0] != '#':
            sig = string_to_sig(line, ln)
            key = (sig['tot'], len(sig['opts']), sig['quirks'], sig['df'])
            bh.setdefault(key, []).append(sig)
    return bh

def parse_ip(ip):
    """Parse fields from a TCP/IP packet into a sig dict to match."""
    tcp = ip.tcp
    mss = 0
    wsc = 0
    quirks = 0
    tstamp = 0

    if (ip.v_hl & 0x0f) > 5:
        quirks |= quirk2bits['I']
    if (tcp.flags & dpkt.tcp.TH_RST) and (tcp.flags & dpkt.tcp.TH_ACK):
        quirks |= quirk2bits['K']
    if tcp.seq == tcp.ack:
        quirks |= quirk2bits['Q']
    if tcp.seq == 0:
        quirks |= quirk2bits['0']
    if (tcp.flags & ~(dpkt.tcp.TH_SYN|dpkt.tcp.TH_ACK|dpkt.tcp.TH_RST|dpkt.tcp.TH_ECE|dpkt.tcp.TH_CWR)):
        quirks |= quirk2bits['F']
    if tcp.data:
        quirks |= quirk2bits['D']

    opts = []
    # XXX - add ilen QUIRK_PAST parsing here
    for opt in dpkt.tcp.parse_opts(tcp.opts):
        try:
            o,d = opt
            if len(d) > 32: raise TypeError
        except TypeError:
            quirks |= quirk2bits['B']
            break
        if o == dpkt.tcp.TCP_OPT_MSS:
            mss = struct.unpack('>H', d)[0]
        elif o == dpkt.tcp.TCP_OPT_WSCALE:
            wsc = ord(d)
        elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
            tstamp, t2 = struct.unpack('>II', d)
            if t2: quirks |= quirk2bits['T']
        opts.append(o)

    if (tcp.flags & dpkt.tcp.TH_ACK): quirks |= quirk2bits['A']
    if (tcp.flags & dpkt.tcp.TH_URG): quirks |= quirk2bits['U']
    if (tcp.off_x2 & 0x0f): quirks |= quirk2bits['X']
    if ip.id == 0: quirks |= quirk2bits['Z']

    return { 'ttl':ip.ttl, 'tot':ip.len,
             'df':int((ip.off & dpkt.ip.IP_DF) != 0),
             'opts':opts, 'mss':mss, 'wss':tcp.win, 'wsc':wsc,
             'tstamp':tstamp, 'quirks':quirks }


def sig_to_string(sig):
    """Convert sig dict to printable fingerprint entry string."""
    mss, wss, = sig['mss'], sig['wss'],
    l = []

    if (mss and wss and not (wss % mss) and (wss/mss) <= 1460): # XXX
        l.append('S%d' % (wss/mss))
    elif (wss and not (wss % 1460)):
        l.append('S%d' % (wss/1460))
    elif (mss and wss and not (wss % (mss+40))):
        l.append('T%d' % (wss/(mss+40)))
    elif (wss and not (wss % 1500)):
        l.append('T%d' % (wss/1500))
    elif wss == 12345:
        l.append('*(12345)')
    else:
        l.append('%d' % wss)

    l.append('%d' % sig['ttl'])
    l.append('%d' % sig['df'])
    if sig['tot'] < PACKET_BIG:
        l.append('%d' % sig['tot'])
    else:
        l.append('*(%d)' % sig['tot'])

    ol = []
    for o in sig['opts']:
        if o == dpkt.tcp.TCP_OPT_NOP: ol.append('N')
        elif o == dpkt.tcp.TCP_OPT_WSCALE:
            if sig.get('wsc_mod', 0) == MOD_CONST and sig['wsc'] == 1:
                ol.append('W*')
            else: ol.append('W%d' % sig['wsc'])
        elif o == dpkt.tcp.TCP_OPT_MSS:
            if sig.get('mss_mod', 0) == MOD_CONST and sig['mss'] == 1:
                ol.append('M*')
            else: ol.append('M%d' % mss)
        elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
            if sig.get('zero_stamp', 0):
                ol.append('T0') # XXX
            elif sig.get('tstamp', 1):
                ol.append('T')
            else:
                ol.append('T0')
        elif o == dpkt.tcp.TCP_OPT_SACKOK:
            ol.append('S')
        elif o == dpkt.tcp.TCP_OPT_EOL:
            ol.append('E')
        else:
            ol.append('?%d' % o)
    if ol:
        l.append(','.join(ol))
    else:
        l.append('.')

    if sig['quirks']:
        quirks = sig['quirks']
        ql = []
        for b in quirk2flags:
            if quirks & b:
                ql.append(quirk2flags[b])
        l.append(''.join(ql))
    else:
        l.append('.')

    if 'os' in sig:
        l.append(sig['os'])
        l.append(sig['desc'])
    else:
        l.extend(('?', '?'))

    return ':'.join(l)

def find_match(bh, **kwargs):
    """Return matching fingerprint entry as a sig dict, or None if not found.

    Keyword arguments (e.g. from a sig dict):

    bh     -- fingerprint entry dict
    ttl    -- IP time-to-live
    tot    -- total IP length
    df     -- has IP_DF set
    opts   -- list of TCP_OPT_* values
    mss    -- TCP_OPT_MSS maximum segment size
    wss    -- TCP window size
    wsc    -- TCP_OPT_WSCALE window scaling factor
    tstamp -- TCP_OPT_TIMESTAMP timestamp
    quirks -- bitmask of QUIRK_* values
    """
    ttl, tot, df, opts, mss, wss, wsc, tstamp, quirks = \
         kwargs['ttl'], kwargs['tot'], kwargs['df'], kwargs['opts'], \
         kwargs['mss'], kwargs['wss'], kwargs['wsc'], kwargs['tstamp'], \
         kwargs['quirks']
    try:
        sigs = bh[(tot,len(opts),quirks,df)]
    except KeyError:
        sigs = ()

    match = {}
    fuzzy = None

    for sig in sigs:
        # tot set to zero means >= PACKET_BIG (100)
        if sig['tot']:
            if (tot ^ sig['tot']): continue
        elif tot < 100: continue

        if (len(opts) ^ len(sig['opts'])): continue

        if (sig['zero_stamp'] ^ int(not tstamp)): continue
        if (sig['df'] ^ df): continue
        if (sig['quirks'] ^ quirks): continue

        # check MSS and WSCALE
        if not sig['mss_mod']:
            if (mss ^ sig['mss']): continue
        elif (mss % sig['mss']): continue

        if not sig['wsc_mod']:
            if (wsc ^ sig['wsc']): continue
        elif (wsc % sig['wsc']): continue

        # then proceed with the most complex WSS check
        mod = sig['wss_mod']
        if mod == 0:
            if (wss ^ sig['wss']): continue
        elif mod == MOD_CONST:
            if (wss % sig['wss']): continue
        elif mod == MOD_MSS:
            if mss and not (wss % mss):
                if ((wss / mss) ^ sig['wss']): continue
            elif not (wss % 1460):
                if ((wss / 1460) ^ sig['wss']): continue
            else: continue
        elif mod == MOD_MTU:
            if mss and not (wss % (mss+40)):
                if ((wss / (mss+40)) ^ sig['wss']): continue
            elif not (wss % 1500):
                if ((wss / 1500) ^ sig['wss']): continue
            else: continue

        # numbers agree, let's check options
        if filter(None, [ x ^ y for x, y in zip(sig['opts'], opts) ]):
            continue

        # Check TTLs last because we might want to go fuzzy
        if sig['ttl'] < ttl:
            fuzzy = sig
            continue

        if 'no_detail' not in sig:
            if sig['ttl'] - ttl > 40:
                fuzzy = sig
                continue

        # Match!
        match.update(sig)
        break

    if not match:
        if fuzzy:
            match.update(fuzzy)
            match['fuzzy'] = True
        elif not df:
            # XXX - GOTO!@#$%
            kwargs['df'] = 1
            match = find_match(bh, **kwargs)

    if match:
        # XXX - move these to reporting? these can be computed
        # even for UNKNOWN matches...
        if (mss & wss):
            if match['wss_mod'] == MOD_MSS:
                if ((wss % mss) and not (wss % 1460)): match['nat'] = 1
            elif match['wss_mod'] == MOD_MTU:
                if ((wss % (mss+40)) and not (wss % 1500)): match['nat'] = 2

        if (df ^ match['df']): match['firewall'] = True

        if tstamp: match['uptime'] = tstamp / 360000

        # XXX - fix below!
        try: match['link'] = mtu2link[mss + 40]
        except KeyError: match['link'] = 'unknown-%d' % mss
        match['distance'] = match['ttl'] - ttl

    return match

class P0f(object):
    def __init__(self, synconf='share/p0f.fp', synackconf='share/p0fa.fp',
                 rstconf='share/p0fr.fp', match=True, rewrite=False):
        self.matchdb = {}
        self.rewritedb = {}
        if synconf:
            bh = load_config(open(synconf))
            if match:
                self.matchdb[dpkt.tcp.TH_SYN] = bh
            if rewrite:
                self.rewritedb[dpkt.tcp.TH_SYN] = self._match_to_rewrite(bh)
        if synackconf:
            bh = load_config(open(synackconf))
            if match:
                self.matchdb[dpkt.tcp.TH_SYN|dpkt.tcp.TH_ACK] = bh
            if rewrite:
                bh = self._match_to_rewrite(bh)
                self.rewritedb[dpkt.tcp.TH_SYN|dpkt.tcp.TH_ACK] = bh
        if rstconf:
            bh = load_config(open(rstconf))
            if match:
                self.matchdb[dpkt.tcp.TH_RST] = bh
                self.matchdb[dpkt.tcp.TH_RST|dpkt.tcp.TH_ACK] = bh
            if rewrite:
                bh = self._match_to_rewrite(bh)
                self.rewritedb[dpkt.tcp.TH_RST] = bh
                self.rewritedb[dpkt.tcp.TH_RST|dpkt.tcp.TH_ACK] = bh

    def _match_to_rewrite(self, matchdb):
        db = {}
        for k, sigs in matchdb.iteritems():
            for sig in sigs:
                db[(sig['os'], sig['desc'])] = sig
        return db

    def match(self, ip):
        """Return matching sig dict for TCP/IP packet, or None."""
        return find_match(self.matchdb[ip.tcp.flags & (dpkt.tcp.TH_SYN|dpkt.tcp.TH_RST|dpkt.tcp.TH_ACK)], **parse_ip(ip))

    def fingerprint(self, ip):
        """Return sig string for TCP/IP packet."""
        return sig_to_string(parse_ip(ip))

    def rewrite(self, ip, os, desc):
        """Rewrite TCP/IP packet to match os, desc fingerprint, returning boolean status."""
        # XXX - descriptions differ by fingerprint database! :-(
        tcp = ip.data
        try:
            bh = self.rewritedb[tcp.flags & (dpkt.tcp.TH_SYN|dpkt.tcp.TH_RST|dpkt.tcp.TH_ACK)]
            sig = bh[(os, desc)]
        except KeyError:
            return False
        # Set options
        mss = 0
        ol = []
        for opt in sig['opts']:
            if opt == dpkt.tcp.TCP_OPT_NOP or opt == dpkt.tcp.TCP_OPT_EOL:
                ol.append(chr(opt))
            elif opt == dpkt.tcp.TCP_OPT_WSCALE:
                ol.append(struct.pack('>BBB', opt, 3, sig['wsc']))
            elif opt == dpkt.tcp.TCP_OPT_MSS and \
                 tcp.flags & (dpkt.tcp.TH_SYN|dpkt.tcp.TH_ACK) == \
                     dpkt.tcp.TH_SYN:
                mss = sig['mss']
                if mss == 1: mss = 1460
                ol.append(struct.pack('>BBH', opt, 4, mss))
            elif opt == dpkt.tcp.TCP_OPT_SACKOK:
                ol.append('\x04\x02')
            elif opt == dpkt.tcp.TCP_OPT_TIMESTAMP:
                if sig['zero_stamp']: ts = 0
                else: ts = int(time.time()) # XXX - should read real ts
                ol.append(struct.pack('>BBII', opt, 10, ts, 0))
        tcp.opts = ''.join(ol)
        tcp.off = (20 + len(tcp.opts)) >> 2

        # Set window size
        mod, win = sig['wss_mod'], sig['wss']
        if mod == MOD_MSS:
            if mss: win *= mss
            else: win *= 1460
        elif mod == MOD_MTU:
            if mss: win *= (mss + 40)
            else: win *= 1500
        tcp.win = win

        # Fix up IP header
        ip.off = sig['df'] and dpkt.ip.IP_DF or 0
        ip.ttl = sig['ttl']
        ip.len = 20 + len(tcp)
        ip.sum = 0

        return True

import dnet, dsniff

class P0f2(dsniff.Handler):
    name = 'p0f2'

    def setup(self):
        self.p0f = P0f()
        self.ipcache = { dpkt.tcp.TH_SYN:{}, dpkt.tcp.TH_RST:{} }
        self.subscribe('pcap', '(tcp[13] & 0x%x != 0)' % (dpkt.tcp.TH_SYN|dpkt.tcp.TH_RST), self.recv_pkt)

    def recv_pkt(self, pc, pkt):
        ip = dpkt.ethernet.Ethernet(pkt).ip
        f = ip.tcp.flags & (dpkt.tcp.TH_SYN|dpkt.tcp.TH_RST)
        if ip.src not in self.ipcache[f]:
            self.ipcache[f][ip.src] = 1
            sig = self.p0f.match(ip)
            print '%s -' % dnet.ip_ntoa(ip.src),
            if sig:
                print '%s %s' % (sig['os'], sig['desc']),
            else:
                print 'UNKNOWN %s' % sig_to_string(parse_ip(ip)),
            l = []
            if 'uptime' in sig:
                l.append('up: %d hrs' % sig['uptime'])
            if 'distance' in sig:
                l.append('distance: %d' % sig['distance'])
            if 'link' in sig:
                l.append('link: %s' % sig['link'])
            if l:
                print '(%s)' % ', '.join(l)
            else:
                print

if __name__ == '__main__':
    dsniff.main()
