#!/usr/bin/env python

# $Id$

import os, time
import dsniff

class MailSnarf(dsniff.Handler):
    def setup(self):
        self.subscribe('*', 'email', self.recv_email)
        self.__last_hdrs = None

    def recv_email(self, hdrs, msgfile):
        """Output mail in BSD mbox format.
        """
        flow = self.flow
        if hdrs != self.__last_hdrs:
            self.__last_hdrs = hdrs
            print 'From mailsnarf', time.ctime(flow.etime)
            for line in open(msgfile):
                line = line.rstrip()
                if line.startswith('From '):
                    print '>%s' % line
                else:
                    print line
        os.unlink(msgfile)

if __name__ == '__main__':
    dsniff.main()
