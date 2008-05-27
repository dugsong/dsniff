# $Id$

import base64, email.Parser
import dsniff
from dsniff.lib import io

POP_NONE, POP_RETR, POP_DATA = range(3)

class POPHandler(dsniff.Handler):
    name = 'pop'
    events = ('auth', 'email')

    def setup(self):
        self.subscribe('service', 'pop', self.recv_flow)

    def recv_flow(self, flow):
        if self in flow.save:
            d = flow.save[self]
        else:
            d = flow.save[self] = { 'state':POP_NONE }

        if flow.server.data:
            if d['state'] == POP_RETR:
                if self.callbacks.get('email') and \
                       flow.server.data.startswith('+OK'):
                    d['state'] = POP_DATA
                    d['msgfile'] = io.Tempfile()
                    d['msgfile'].write(flow.server.data.split('\n', 1)[1])
                else:
                    d['state'] = POP_NONE
            elif d['state'] == POP_DATA:
                if flow.server.data.endswith('\r\n.\r\n'):
                    d['msgfile'].write(flow.server.data[:-5])
                    d['msgfile'].close()
                    # XXX - don't litter
                    d['msgfile'].rename('pop.msg')
                    parser = email.Parser.Parser()
                    msg = parser.parse(open(d['msgfile'].name),
                                       headersonly=True)
                    self.publish('email', msg._headers,
                                 d['msgfile'].name)
                    d['state'] = POP_NONE
                else:
                    d['msgfile'].write(flow.server.data)
        elif flow.client.data:
            for line in flow.client.readlines():
                if d['state'] == POP_NONE:
                    if line.startswith('RETR'):
                        d['state'] = POP_RETR
                    elif line.startswith('USER'):
                        d['username'] = line.split(' ', 1)[1]
                    elif line.startswith('PASS') and d.get('username'):
                        password = line.split(' ', 1)[1]
                        if self.callbacks.get('auth'):
                            self.publish('auth', d.pop('username'), password)
                    elif line.startswith('AUTH') and \
                             self.callbacks.get('auth'):
                        l = line.split()
                        if l[1] in ('PLAIN', 'LOGIN'):
                            username, password = \
                                base64.decodestring(l[2]).split('\x00')[-2:]
                        self.publish('auth', username, password)

if __name__ == '__main__':
    dsniff.test()
