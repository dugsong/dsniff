# $Id$

import re
import dsniff
from dsniff.lib import html
import _webmail

class YmailParser(_webmail.Parser):
    hdrs_re = re.compile(r'<table class=messageheader .*?>(?P<hdrs>.*?)</table>', re.DOTALL)
    hdr_re = re.compile(r'<tr><td class=label nowrap>(?P<k>.*?)</td><td>(?P<v>.*?)</td></tr>', re.DOTALL)
    body_re = re.compile(r'<div id=message>(?P<body>.*?)</div>\n\n<!-- END TOC -->', re.DOTALL)
    client_addrs = {}

    def handle_request(self, method, uri, version):
        if method == 'GET' and uri.startswith('/ym/ShowLetter'):
            self.collect_response(self.__parse_get)
        elif method == 'POST' and uri.startswith('/ym/Compose'):
            self.collect_request(self.__parse_post)

    def __parse_get(self, flow, buf):
        hdrs = self.hdrs_re.search(buf).group('hdrs')
        hdrs = [ (k.strip(':'),
                  # XXX - hack around HREFs in From: value
                  html.decode(html.strip(v.split('&nbsp;&nbsp;')[0])))
                 for k, v in self.hdr_re.findall(buf) ]
        d = dict(hdrs)
        # XXX - track client addrs by IP - should use cookie instead?
        self.client_addrs[flow.client.addr] = d.get('To', '')
        body = self.body_re.search(buf).group('body')
        if hdrs and body:
            self.publish_email(hdrs, body)

    def __parse_post(self, flow, buf):
        d = self.get_postvars(buf)
        hdrs = [ ('From', self.client_addrs.get(flow.client.addr, '')),
                 ('To', d.get('To', [''])[0]),
                 ('Subject', d.get('Subj', [''])[0]) ]
        body = d.get('Body', [''])[0]
        if hdrs and body:
            self.publish_email(hdrs, body)

class YmailHandler(_webmail.Handler):
    name = 'yahoomail'
    parser = YmailParser

if __name__ == '__main__':
    dsniff.test()

