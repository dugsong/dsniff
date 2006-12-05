#!/usr/bin/env python

# $Id$

import os, re, sys, time
import dpkt, dsniff

class Ngrep(dsniff.Handler):
    name = 'ngrep'
    pat = None
    hex = kill = quiet = noheader = raw = False

    def setup(self):
        if os.isatty(sys.stdout.fileno()):
            def _color(s, arrow):
                print { '>':'\033[31m%s\033[0m',
                        '<':'\033[34m%s\033[0m' }[arrow] % s
        else:
            def _color(s, arrow):
                print s
        self.color = _color
        self.subscribe('flow', '', self.recv_flow)

    def _grep_data(self, flow, buf, arrow):
        if self.pat is None or self.pat.search(buf):
            if not self.noheader:
                print '-----------------'
                print time.strftime('%x %X', time.localtime(flow.etime)),
                print flow.__str__(arrow)
            if self.hex:
                self.color(dpkt.hexdump(str(buf)), arrow)
            elif self.raw:
                flow.save['rawf'].write(buf)
            elif not self.quiet:
                self.color(repr(buf), arrow)
            if self.kill:
                flow.kill()

    def recv_flow(self, flow):
        if self.raw:
            if flow.state == dsniff.FLOW_START:
                flow.save['rawf'] = open('/tmp/%s.flow' % id(flow), 'wb')
            elif flow.state == dsniff.FLOW_END:
                flow.save['rawf'].close()
        if flow.client.data:
            self._grep_data(flow, flow.client.data, '>')
        elif flow.server.data:
            self._grep_data(flow, flow.server.data, '<')

class NgrepProgram(dsniff.Program):
    def getopt(self, argv):
        super(NgrepProgram, self).getopt(argv)
        if self.args:
            dsniff.config['ngrep'] = { 'pat':re.compile(self.args.pop(0)) }

if __name__ == '__main__':
    dsniff.set_usage('%prog [options] [pattern [filter]]')
    dsniff.add_option('-x', dest='ngrep.hex', action='store_true',
                      help='hexdump output')
    dsniff.add_option('-k', dest='ngrep.kill', action='store_true',
                      help='kill matching TCP connections')
    dsniff.add_option('-q', dest='ngrep.quiet', action='store_true',
                      help='no content output')
    dsniff.add_option('-n', dest='ngrep.noheader', action='store_true',
                      help='no header output')
    dsniff.add_option('-r', dest='ngrep.raw', action='store_true',
                      help='raw output')
    dsniff.main()
