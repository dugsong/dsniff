# $Id$

import re
import dsniff
from dsniff.lib import html
import _webmail

class FastmailParser(_webmail.Parser):
    hdr_re = re.compile(r'<th class="DatTh" .*?>(?P<k>.*?)</th> <td class="DatTd" .*?>(?P<v>.*?)</td>', re.DOTALL)
    body_re = re.compile(r'<!-- begin message -->\n\n(?P<body>.*?)<!-- end message -->', re.DOTALL)

    def handle_request(self, method, uri, version):
        if method == 'GET' and uri.startswith('/mail/?'):
            self.collect_response(self.__parse_get)
        elif method == 'POST' and uri.startswith('/mail/?'):
            self.collect_request(self.__parse_post)

    def __parse_post(self, flow, buf):
        d = self.get_postvars(buf)
        if 'FMC-MsgMessage' in d:
            hdrs = [ ('To', d['FMC-MsgTo'][0]),
                     ('Subject', d['FMC-MsgSubject'][0]),
                     ('Cc', d['FMC-MsgCc'][0]) ]
            body = d['FMC-MsgMessage'][0]
            if hdrs and body:
                self.publish_email(hdrs, body)

    def __parse_get(self, flow, buf):
        hdrs = []
        for k, v in self.hdr_re.findall(buf):
            k = k.strip('&nbsp;')
            if ' ' not in k:
                v = html.decode(html.strip(v))
                v = v.strip(' [Add]') # XXX - addrs
                v = v.split(' \xa0')[0] # XXX - date
                hdrs.append((k, v))
        m = self.body_re.search(buf)
        if hdrs and m:
            self.publish_email(hdrs, m.group('body'))

class FastmailHandler(_webmail.Handler):
    name = 'fastmail'
    parser = FastmailParser

if __name__ == '__main__':
    dsniff.test()
