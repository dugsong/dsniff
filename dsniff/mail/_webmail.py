# $Id$

import os, rfc822
import dsniff
from dsniff.lib import http, io

class Parser(http.HttpParser):
    def __init__(self, handler):
        super(Parser, self).__init__()
        self.__handler = handler
        self.__f = self.__get_response = None

    def collect_request(self, callback):
        self.__f = io.Tempfile()
        self.__callback = callback

    def collect_response(self, callback):
        self.__get_response = 1
        self.__callback = callback

    def handle_headers(self, hdrs):
        self.__ctype = hdrs.get('content-type', '')

    def handle_response(self, version, status, reason):
        if self.__get_response:
            self.__f = io.Tempfile()

    def handle_body(self, buf):
        if self.__f:
            self.__f.write(buf)

    def handle_end(self):
        if self.__f:
            self.__f.close()
            self.__callback(self.__handler.flow, open(self.__f.name).read())
            os.unlink(self.__f.name)
        self.__f = self.__get_response = None

    def get_postvars(self, buf):
        return http.parse_POST(self.__ctype, buf)

    def publish_email(self, hdrs, body):
        f = io.Tempfile(prefix='email')
        hdrs = dict(hdrs)
        if 'Date' not in hdrs:
            hdrs['Date'] = rfc822.formatdate(self.__handler.flow.etime)
        for k, v in hdrs.iteritems():
            f.write('%s: %s\n' % (k, v))
        f.write('\n')
        f.write(body)
        f.close()
        self.__handler.publish('email', dict(hdrs), f.name)

class Handler(dsniff.Handler):
    events = ('email', )

    def setup(self):
        self.subscribe('service', self.name, self.recv_flow)

    def recv_flow(self, f):
        if f.state == dsniff.FLOW_START:
            f.save['http'] = self.parser(self)
        elif f.state == dsniff.FLOW_CLIENT_DATA:
            f.save['http'].feed(f.client.data)
        elif f.state == dsniff.FLOW_SERVER_DATA:
            f.save['http'].feed(f.server.data)
