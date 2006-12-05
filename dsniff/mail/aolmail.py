# $Id$

import re
import dsniff
from dsniff.lib import json
import _webmail

class AOLMailParser(_webmail.Parser):
    hdr_map = {
        'sentTime':'Date', 'displayTo':'To', 'displayFrom':'From',
        'displayCc':'Cc', 'messageID':'Message-Id', 'subject':'Subject'
        }
    msg_re = re.compile(r'^message\.(?P<k>.*?) = (?P<v>.*);$')

    def handle_request(self, method, uri, version):
        if method == 'GET' and 'GetMessage.aspx' in uri:
            self.collect_response(self.__parse_get)
        elif method == 'POST':
            self.collect_request(self.__parse_post)

    def __parse_post(self, flow, buf):
        d = self.get_postvars(buf)
        hdrs = [ (k, d[k][0]) for k in ('From', 'To', 'Cc', 'Subject')
                 if k in d and d[k][0]]
        body = d['PlainBody'][0]
        if hdrs and body:
            self.publish_email(hdrs, body)

    def __parse_get(self, flow, buf):
        hdrs, body = [], None
        for line in buf.splitlines():
            m = self.msg_re.match(line.strip())
            if m:
                k, v = m.group('k'), m.group('v')
                if k in self.hdr_map:
                    v = json.parse(v)
                    if v: hdrs.append((self.hdr_map[k], v))
                elif k == 'body':
                    body = json.parse(v)
        if hdrs and body:
            self.publish_email(hdrs, body)

class AOLMailHandler(_webmail.Handler):
    name = 'aolmail'
    parser = AOLMailParser

if __name__ == '__main__':
    dsniff.test()
