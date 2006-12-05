# $Id$

import re
import dsniff
from dsniff.lib import html
import _webmail

class HotmailParser(_webmail.Parser):
    hdrs_body_re = re.compile(r'<table class="TH">(?P<hdrs>.*?)</table>.*?<table class="OO">.*?</table><table .*?> \n <tr><td>(?P<body>.*?)</td></tr>\n</table>\n</td></tr></table><div class="HT" ', re.DOTALL)
    hdr_re = re.compile(r'<tr><td nowrap>(?P<k>.*?)</td><td>(?P<v>.*?)</td></tr>', re.DOTALL)

    def handle_request(self, method, uri, version):
        if method == 'GET' and uri.startswith('/cgi-bin/getmsg'):
            self.collect_response(self.__parse_get)
        elif method == 'POST' and uri.startswith('/cgi-bin/premail'):
            self.collect_request(self.__parse_post)

    def __parse_post(self, flow, buf):
        d = self.get_postvars(buf)
        hdrs = [ ('From', '%s@hotmail.com' % d['login'][0]),
                 ('To', d['to'][0]), ('Subject', d['subject'][0]) ]
        body = d['body'][0]
        if hdrs and body:
            self.publish_email(hdrs, body)

    def __parse_get(self, flow, buf):
        m = self.hdrs_body_re.search(buf)
        body = m.group('body')
        hdrs = [ (k.replace('&nbsp;', '').strip(':'), html.decode(v))
                 for k, v in self.hdr_re.findall(m.group('hdrs')) ]
        self.publish_email(hdrs, body)

class HotmailHandler(_webmail.Handler):
    name = 'hotmail'
    parser = HotmailParser

if __name__ == '__main__':
    dsniff.test()

