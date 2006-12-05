# $Id$

import os, sys, tempfile

PATH_SHARE='%s:%s:.' % \
            (os.path.join(sys.prefix, 'share', 'dsniff'),
             os.path.realpath(os.path.join(__file__, '..', '..', '..', 'etc')))

def path_open(filename, path=PATH_SHARE):
    try:
        return open(filename)
    except IOError:
        pass
    for pdir in path.split(':'):
        try:
            return open(os.path.join(pdir, filename))
        except IOError:
            pass
    raise IOError, "couldn't find %s in %s" % (filename, path)

class Tempfile(object):
    """Like tempfile.NamedTemporaryFile minus the implicit unlink on close.
    """
    def __init__(self, dir=None, prefix='tmp'):
        fd, self.name = tempfile.mkstemp(prefix=prefix, dir=dir)
        self.dir = dir or tempfile.gettempdir()
        self.f = os.fdopen(fd, 'w')
    def __getattr__(self, k):
        return getattr(self.f, k)
    def rename(self, newname):
        oldname = self.name
        self.name = os.path.join(self.dir, newname)
        return os.rename(oldname, self.name)
