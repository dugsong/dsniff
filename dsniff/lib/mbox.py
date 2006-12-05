# $Id$

import mime

class MboxParser(mime.MimeParser):
    def _parse_start(self):
        line = self.getline()
        if line.startswith('From '):
            self.handle_mbox_from(line)
        else:
            raise ParseError, 'expected From mbox line, got %r' % line
        self._parse_next = self._parse_field

    def handle_mbox_from(self, line):
        pass

    def _parse_body(self, body):
        # XXX - replace '\n>From' with '\nFrom'
        super(MboxParser, self)._parse_body(body)
