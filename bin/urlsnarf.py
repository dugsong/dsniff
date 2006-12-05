#!/usr/bin/env python

# $Id$

import base64, time
import dsniff
from dsniff.lib import http

class UrlParser(http.HttpParser):
    def __init__(self, flow):
        super(UrlParser, self).__init__(self)
        self.flow = flow

    def handle_request(self, method, uri, version):
        self.req = { 'method':method, 'uri':uri, 'version':version }

    def _get_http_user(self, hdrs):
        if 'authorization' in hdrs:
            scheme, auth = hdrs['authorization'].split(None, 1)
            if scheme == 'Basic':
                return base64.decodestring(auth).split(':')[0]
        return '-'

    def handle_headers(self, hdrs):
        d = self.req
        d['ip'] = self.flow.src
        d['user'] = self._get_http_user(hdrs)
        if d['uri'].startswith('http'):
            d['url'] = d['uri']
        else:
            d['url'] = 'http://%s%s' % (hdrs.get('host', self.flow.dst),
                                        d['uri'])
        for k in ('referer', 'user-agent'):
            d[k] = hdrs.get(k, '-')
        d['timestamp'] = \
            time.strftime('%e/%b/%Y:%X', time.gmtime(self.flow.etime)).strip()
        print repr('%(ip)s - %(user)s [%(timestamp)s] '
                   '"%(method)s %(url)s" - - '
                   '"%(referer)s" "%(user-agent)s"' % d).strip("'")

class URLSnarf(dsniff.Handler):
    def setup(self):
        self.subscribe('service', 'http', self.recv_flow)

    def recv_flow(self, f):
        if f.state == dsniff.FLOW_START:
            f.client.save['urlparser'] = UrlParser(f)
        elif f.state == dsniff.FLOW_CLIENT_DATA:
            try:
                f.client.save['urlparser'].feed(f.client.data)
            except http.mime.ParseError:
                pass

if __name__ == '__main__':
    dsniff.main()
