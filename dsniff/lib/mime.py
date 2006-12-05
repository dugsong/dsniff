# $Id$

"""Streaming MIME parser, ala sgmllib."""

class NeedInput(Exception): pass
class ParseError(Exception): pass

class MimeParser(object):
    def __init__(self, *args, **kwargs):
        self.reset()

    def reset(self, data=None):
        self._field = None
        self._data = data
        self._parse_next = self._parse_start

    def getline(self):
        i = self._data.find('\n')
        if i < 0:
            raise NeedInput
        line, self._data = self._data[:i+1], self._data[i+1:]
        return line

    def feed(self, data):
        if self._data:
            self._data += data
        else:
            self._data = data
        while self._data:
            try:
                self._parse_next()
            except NeedInput:
                break

    def _parse_start(self):
        self.handle_start()
        self._parse_next = self._parse_field

    def _parse_field(self):
        line = self.getline()
        if line.startswith(' ') or line.startswith('\t'):
            # line continuation
            self._field = '%s %s' % (self._field, line.strip())
        else:
            if self._field:
                # if we had a previous field, parse it
                name, value = self._field.split(':', 1)
                value = value.strip()
                self.handle_field(name, value)
                """
                try:
                    m = getattr(self, 'do_%s' % name.lower().replace('-', '_'))
                    m(name, value)
                except AttributeError:
                    pass
                """
                self._field = None
            line = line.strip()
            if line:
                self._field = line
            else:
                self._end_fields()

    def _end_fields(self):
        self._parse_next = self._parse_body

    def _parse_body(self):
        self.handle_body(self._data)
        self.handle_end()
        self.reset()

    def handle_start(self):
        """Override to handle start of a message."""
        pass

    def handle_end(self):
        """Override to handle the end of a message."""
        pass

    def handle_field(self, name, value):
        """Override to handle header field."""
        pass

    def handle_body(self, body):
        """Override to handle some body data (not necessarily all of it)."""
        pass

