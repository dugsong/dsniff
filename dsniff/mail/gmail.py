# $Id$

import re
import dsniff
from dsniff.lib import json
import _webmail

class GmailParser(_webmail.Parser):
    data_re = re.compile(r'D\((.*?)\);\n', re.DOTALL)

    def handle_request(self, method, uri, version):
        if method == 'GET' and uri.startswith('/mail/') and 'view=cv' in uri:
            self.collect_response(self.__parse_get)
        elif method == 'POST' and uri.startswith('/mail/') and 'ik=' in uri:
            self.collect_request(self.__parse_post)

    def __parse_post(self, flow, buf):
        d = self.get_postvars(buf)
        if d:
            hdrs = [ (h.capitalize(), d[h][0].rstrip(', '))
                     for h in ('from', 'to', 'subject', 'cc') if d[h][0] ]
            self.publish_email(hdrs, '\n'.join(d['msgbody']))

    def __parse_get(self, flow, buf):
        hdrs, body = [], []
        for s in self.data_re.findall(buf):
            s = s.replace('\n', '')
            for i in range(2): # XXX - lame
                s = s.replace(',,', ',None,')
            l = json.parse(s)
            if l[0] == 'mi':
                if hdrs and body:
                    # XXX - handle message threads
                    self.publish_email(hdrs, '\n'.join(body))
                hdrs, body = [], []
                hdrs.append(('From', '%s <%s>' % (l[6], l[8])))
                hdrs.append(('To', ', '.join(l[11])))
                if l[12]:
                    hdrs.append(('Cc', ', '.join(l[12])))
                if l[14]:
                    hdrs.append(('Reply-To', l[14][0]))
                hdrs.append(('Date', l[15]))
                hdrs.append(('Subject', l[16]))
                hdrs.append(('Message-Id', l[-1]))
            elif l[0] == 'mb':
                body.append(l[1])
        if hdrs and body:
            self.publish_email(hdrs, '\n'.join(body))

class Gmail(_webmail.Handler):
    name = 'gmail'
    parser = GmailParser

if __name__ == '__main__':
    dsniff.test()
