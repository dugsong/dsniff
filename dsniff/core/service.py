# $Id$

import dsniff
import sys
from dsniff.core import flow
from dsniff.lib import net

# XXX - override some service definitions
_services = {
    'aolmail':'tcp and dst port 80 and dst net 205.188.0.0/16',
    'http':'tcp and dst port %s' % ' or '.join([ str(p) for p in (80, 98, 280, 591, 3128, 3132, 4480, 5490, 8000, 8080, 11371) ]),
    'fastmail':'tcp and dst port 80 and dst net 66.111.0.0/20',
    'gmail':'tcp and dst port 80 and dst net 64.233.160.0/19 or 66.249.64.0/19 or 72.14.0.0/16 or 64.68.80.0/21',
    'hotmail':'tcp and dst port 80 and dst net 64.4.0.0/18',
    'lycosmail':'tcp and dst port 80 and dst net 208.36.123.0/24',
    'yahoomail':'tcp and dst port 80 and dst net 66.163.160.0/19 or 64.58.76.0/22 or 64.41.224.0/23',
    'dns':'dst port 53',
    }

try:
    import appid
    appid_loaded = True
except ImportError, e:
    appid_loaded = False
    pass

class ServiceHandler(dsniff.Handler):
    name = 'service'
    auto = False

    def setup(self):
        if self.auto:
            self.subscribe('flow', 'tcp or udp', self.recv_flow)
        else:
            self._register = self.__proxy_register
            self._unregister = self.__proxy_unregister

    def recv_flow(self, f):
        if '_service' in f.save:
            self.publish(f.save['_service'], f)
            return
        if appid_loaded:
            if f.state == flow.FLOW_START:
                for half in f.half.itervalues():
                    half.save['_appid'] = appid.appid()
                    half.save['_appid_buf'] = half.data or ''
            app = (-1, 0)
            for half in f.half.itervalues():
                if half.data:
                    half.save['_appid_buf'] += half.data
                    print sys.stderr, 'appid about to process %s s:%s d:%s' % (f.p, f.sport, f.dport)
                    app = half.save['_appid'].process(f.p, f.sport, f.dport, half.data)
                    print sys.stderr, 'appid returned %s' % (app,)
                    if app[0] != 0: # APPID_CONTINUE
                        break
            if app[0] not in (65535, -1, 0): # XXX: 65535 is because application is currently unsigned
                event = appid.app_to_name(app[0]).lower()
                print 'appid match:', event
                if event in self.callbacks:
                    f.save['_service'] = event
                    f.save['_confidence'] = app[1]
                    for half in f.half.itervalues():
                        half.data = half.save.pop('_appid_buf')
                        del half.save['_appid']
                    f.state = flow.FLOW_START
                    self.publish(event, f)
                    if f.client.data:
                        f.state = flow.FLOW_CLIENT_DATA
                        self.publish(event, f)
                    if f.server.data:
                        f.state = flow.FLOW_SERVER_DATA
                        self.publish(event, f)
                else:
                    for half in f.half.itervalues():
                        del half.save['_appid_buf']
                        del half.save['_appid']
                    f.unregister(self.recv_flow)

    def __event_to_fcaps(self, event):
        if event in _services:
            return [ _services[event] ]
        svcs = net.serv_aton(event)
        l = []
        for p in (1, 6, 17):
            ports = [ str(svc[1]) for svc in svcs if svc[0] == p ]
            if ports:
                l.append('%s and dst port %s' %
                         (net.proto_ntoa(p), ' or '.join(ports)))
        return l

    def __proxy_register(self, event, callback):
        # XXX - just proxy to FlowHandler
        fcaps = self.__event_to_fcaps(event)
        for fcap in fcaps:
            self.subscribe('flow', fcap, callback)

    def __proxy_unregister(self, event, callback):
        # XXX - just proxy to FlowHandler
        fcaps = self.__event_to_fcaps(event)
        for fcap in fcaps:
            self.unsubscribe('flow', fcap, callback)
