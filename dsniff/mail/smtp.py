# $Id$

import base64, email.Parser
import dsniff
from dsniff.lib import io

SMTP_NONE, SMTP_AUTH, SMTP_HELO, SMTP_MAIL, SMTP_RCPT, SMTP_DATA = range(6)

class SMTPHandler(dsniff.Handler):
    name = 'smtp'
    events = ('auth', 'email')

    def setup(self):
        self.subscribe('service', 'smtp', self.recv_flow)

    def recv_flow(self, flow):
        if not flow.client.data:
            return
        if self in flow.save:
            d = flow.save[self]
        else:
            d = flow.save[self] = { 'state':SMTP_NONE }

        for line in flow.client.readlines():
            if d['state'] == SMTP_DATA:
                if line == '.':
                    if 'email' in self.callbacks:
                        d['msgfile'].close()
                        # XXX - don't litter
                        d['msgfile'].rename('smtp.msg')
                        parser = email.Parser.Parser()
                        msg = parser.parse(open(d['msgfile'].name),
                                           headersonly=True)
                        self.publish('email', msg._headers,
                                     d['msgfile'].name)
                    d['state'] = SMTP_HELO
                elif 'email' in self.callbacks:
                    d['msgfile'].write(line)
                    d['msgfile'].write('\r\n')
            elif line.strip():
                cmd = line.split()[0]
                if cmd == 'RSET':
                    d['state'] = SMTP_HELO
                elif line.startswith('AUTH LOGIN'):
                    l = line.split()
                    d['user'] = base64.decodestring(l[2])
                    d['state'] = SMTP_AUTH
                elif d['state'] == SMTP_AUTH:
                    if 'auth' in self.callbacks:
                        self.publish('auth', d.pop('user'),
                                     base64.decodestring(line), {})
                    d['state'] = SMTP_HELO
                elif d['state'] == SMTP_NONE and cmd in ('HELO', 'EHLO'):
                    d['state'] = SMTP_HELO
                elif d['state'] == SMTP_HELO and \
                         cmd in ('MAIL', 'SEND', 'SAML'):
                    #d['from'] = line.split('<', 1)[1].split('>', 1)[0]
                    d['state'] = SMTP_MAIL
                elif d['state'] == SMTP_MAIL and cmd == 'RCPT':
                    d['state'] = SMTP_RCPT
                elif d['state'] == SMTP_RCPT and cmd == 'DATA':
                    d['state'] = SMTP_DATA
                    if 'email' in self.callbacks:
                        d['msgfile'] = io.Tempfile()

if __name__ == '__main__':
    dsniff.test()
