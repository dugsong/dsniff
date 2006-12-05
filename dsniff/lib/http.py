# $Id$

"""HTTP feedparser."""

import cgi, cStringIO, zlib
import mime

def parse_POST(content_type, buf):
    """Return dict of POST variables given the Content-Type header value
    and the content buffer.
    """
    ctype, pdict = cgi.parse_header(content_type)
    if ctype == 'multipart/form-data':
        return cgi.parse_multipart(cStringIO.StringIO(buf), pdict)
    elif ctype == 'application/x-www-form-urlencoded':
        return cgi.parse_qs(buf)
    return {}

class HttpParser(mime.MimeParser):
    methods = dict.fromkeys((
        'GET', 'PUT', 'ICY',
        'COPY', 'HEAD', 'LOCK', 'MOVE', 'POLL', 'POST',
        'BCOPY', 'BMOVE', 'MKCOL', 'TRACE', 'LABEL', 'MERGE',
        'DELETE', 'SEARCH', 'UNLOCK', 'REPORT', 'UPDATE', 'NOTIFY',
        'BDELETE', 'CONNECT', 'OPTIONS', 'CHECKIN',
        'PROPFIND', 'CHECKOUT', 'CCM_POST',
        'SUBSCRIBE', 'PROPPATCH', 'BPROPFIND',
        'BPROPPATCH', 'UNCHECKOUT', 'MKACTIVITY',
        'MKWORKSPACE', 'UNSUBSCRIBE', 'RPC_CONNECT',
        'VERSION-CONTROL',
        'BASELINE-CONTROL'
        ))
    proto = 'HTTP'

    def reset(self, data=None):
        """Reset HTTP parser."""
        super(HttpParser, self).reset(data)
        self.body_len = self.chunk_len = self.zlib = self.gzcnt = None
        self.headers = {}

    def _parse_start(self):
        # XXX - RFC 2616, 4.1
        while True:
            line = self.getline().strip()
            if line: break

        l = line.split(None, 2)
        if len(l) == 2:
            l.append('')    # XXX - empty version

        if l[0].startswith(self.proto):
            # HTTP response
            version, status, reason = l
            status = int(status)
            if status == 204 or status == 304 or 100 <= status < 200:
                self.body_len = 0
            self.handle_response(version, status, reason)
        else:
            # HTTP request
            try:
                method, uri, version = l
            except ValueError:
                return
            if method not in self.methods or \
                   not version.startswith(self.proto):
                return  # XXX - be forgiving of mid-stream parsing
            if method == 'HEAD':
                self.body_len = 0
            self.handle_request(method, uri, version)

        super(HttpParser, self)._parse_start()

    def handle_headers(self, headers):
        """Overload to handle a dict of HTTP headers."""
        pass

    def handle_request(self, method, uri, version):
        """Overload to handle a new HTTP request."""
        pass

    def handle_response(self, version, status, reason):
        """Overload to handle a new HTTP response."""
        pass

    def handle_field(self, name, value):
        """HTTP header field collector."""
        name = name.lower()
        self.headers[name] = value

    def _end_fields(self):
        self.handle_headers(self.headers)
        self._zlib_setup(self.headers)
        if self.headers.get('transfer-encoding', '').lower() == 'chunked':
            self._parse_next = self.__parse_body_chunked
        elif self.body_len == 0:
            self.reset(self._data)
        elif 'content-length' in self.headers:
            self.body_len = int(self.headers['content-length'])
            self._parse_next = self.__parse_body_len
        elif self.headers.get('connection', '').lower() == 'keep-alive':
            self.reset(self._data)
        else:
            self._parse_next = self.__parse_body_close

    def _zlib_setup(self, hdrs):
        if 'gzip' in hdrs.get('content-encoding', '') or \
           'gzip' in hdrs.get('transfer-encoding', ''):
            self.zlib = zlib.decompressobj(-zlib.MAX_WBITS)
            self.gzcnt = 10     # XXX - vanilla gzip hdr len
        else:
            self.zlib = None
            self.gzcnt = 0

    def _zlib_decompress(self, buf):
        if self.zlib is not None:
            if self.gzcnt:
                n = min(self.gzcnt, len(buf))
                self.gzcnt -= n
                buf = buf[n:]
            if buf:
                buf = self.zlib.decompress(buf)
        return buf

    def __parse_body_close(self):
        self.handle_body(self._zlib_decompress(self._data))
        self._data = ''
        # XXX - self.handle_end() never called!

    def __parse_body_len(self):
        buf = self._data[:self.body_len]
        self.handle_body(self._zlib_decompress(buf))
        self._data = self._data[self.body_len:]
        self.body_len -= len(buf)
        if not self.body_len:
            self.handle_end()
            self.reset(self._data)

    def __parse_body_chunked(self):
        if self.chunk_len is None:
            line = self.getline()
            self.chunk_len = int(line.split(None, 1)[0], 16)
            if self.chunk_len == 0:
                self.chunk_len = -1
        elif self.chunk_len > 0:
            buf = self._data[:self.chunk_len]
            s = self._zlib_decompress(buf)
            if s:
                self.handle_body(s)
            self._data = self._data[self.chunk_len:]
            self.chunk_len -= len(buf)
        else:
            line = self.getline()
            if self.chunk_len < 0:
                self.handle_end()
                self.reset(self._data)
            else:
                self.chunk_len = None

if __name__ == '__main__':
    import sys
    class TestParser(HttpParser):
        def handle_request(self, *args):
            print 'REQ:', args

        def handle_response(self, *args):
            print 'RESPONSE:', args

        def handle_headers(self, headers):
            print 'HDRS:', headers

        def handle_body(self, body):
            print 'BODY:', len(body), `body`#`body[:50]`

    #buf = 'GET /download.html HTTP/1.1\r\nHost: www.ethereal.com\r\nUser-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113\r\nAccept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,image/jpeg,image/gif;q=0.2,*/*;q=0.1\r\nAccept-Language: en-us,en;q=0.5\r\nAccept-Encoding: gzip,deflate\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\nKeep-Alive: 300\r\nConnection: keep-alive\r\nReferer: http://www.ethereal.com/development.html\r\n\r\n'
    buf = open(sys.argv[1]).read()
    TestParser().feed(buf)
