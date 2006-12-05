# $Id$

try:
    from __builtin__ import set
except ImportError:
    from sets import Set as set
import fnmatch, optparse, os, signal, sys, types
import event

_op = optparse.OptionParser(usage='%prog [options] [filter]')
handlers = {}   # name:handler instances
config = {}     # name:{var:val} handler configs

add_option = _op.add_option
set_usage = _op.set_usage

class _MetaHandler(type):
    def __new__(cls, clsname, clsbases, clsdict):
        t = type.__new__(cls, clsname, clsbases, clsdict)
        if clsdict.get('name'):
            t._subclasses[clsdict['name']] = t
        return t

class Handler(object):
    """Pub/sub handler interface.
    """
    __metaclass__ = _MetaHandler  # XXX - stuff class into Handler.subclasses

    name = None     # handler name
    events = ()     # list of events published

    _subclasses = {}    # name:handler class

    def __init__(self, *args, **kwargs):
        global config
        if self.name in config:
            self.__dict__.update(config[self.name]) # XXX
        self.subscriptions = {}
        self.callbacks = {}
        self.setup()

    def setup(self):
        """Override with any setup actions (e.g. subscriptions, etc.)."""
        pass

    def subscribe(self, name, event, callback):
        """Subscribe to a handler's event.

        Arguments:
        name     -- name of handler (or match pattern)
        event    -- name of event published by handler
        callback -- callback to be invoked
        """
        if '*' in name:
            found = False
            for x in fnmatch.filter(Handler._subclasses.iterkeys(), name):
                if event in Handler._subclasses[x].events:
                    self.subscribe(x, event, callback)
                    found = True
            if not found:
                raise RuntimeError, 'no matching handlers found'
            return
        if name not in handlers:
            if name != self.name:
                # XXX - auto-instantiate handler
                handlers[name] = Handler._subclasses[name]()
            else:
                handlers[name] = self
        pub = handlers[name]
        pub._register(event, callback)
        if pub not in self.subscriptions:
            self.subscriptions[pub] = set()
        self.subscriptions[pub].add((event, callback))

    def unsubscribe(self, name, event, callback):
        """Unsubscribe from a handler's event.

        Arguments:
        name     -- name of handler (or match pattern)
        event    -- name of event published by handler
        callback -- callback to be invoked
        """
        pub = handlers[name]
        if pub in self.subscriptions:
            pub._unregister(event, callback)
            self.subscriptions[pub].remove((event, callback))

    def _register(self, event, callback):
        """Register subscription from another handler."""
        if event not in self.callbacks:
            self.callbacks[event] = set()
        self.callbacks[event].add(callback)

    def _unregister(self, event, callback):
        """Remove subscription from another handler."""
        l = self.callbacks[event]
        l.remove(callback)
        if not l:
            del self.callbacks[event]

    def publish(self, event, *args, **kwargs):
        """Send an event to any registered listeners."""
        if event in self.callbacks:
            for callback in self.callbacks[event]:
                # XXX - unsub from within callback breaks iteration
                callback(*args, **kwargs)
        else:
            print >>sys.stderr, self.name, 'publishing %s to nobody!' % event

    def teardown(self):
        """Override to perform any cleanup actions."""
        pass

    def delete(self):
        for pub, subscriptions in self.subscriptions.iteritems():
            for event, callback in subscriptions:
                pub._unregister(event, callback)
        self.subscriptions.clear()
        self.teardown()
        # XXX - send status to our subscribers?

    # XXX - add event functions
    signal = event.signal
    timeout = event.timeout
    abort = event.abort

def find_subclasses(cls, module, default=[]):
    """Return a list of public subclasses of a class from a module."""
    l = []
    for name in [ x for x in dir(module) if not x.startswith('_') ]:
        o = getattr(module, name)
        if isinstance(o, (type, types.ClassType)) and issubclass(o, cls):
            l.append(o)
    if not l:
        l = default
    return l

class Program(object):
    def __init__(self):
        add_option('-i', action='append', dest='pcap.interfaces',
                   metavar='INPUT', default=[],
                   help='input device or filename')
        add_option('-s', dest='pcap.snaplen', type='int',
                   metavar='SNAPLEN', default=31337,
                   help='capture snapshot length')
        add_option('-d', action='count', dest='pcap.debug',
                   help='debug level')
        self.opts = None
        self.args = ()

    def setup(self):
        """Override with any setup actions (such as adding options, etc.)"""
        pass

    def teardown(self):
        """Override with any teardown actions."""
        pass

    def getopt(self, argv):
        global _op, config
        self.opts, self.args = _op.parse_args(argv)
        # XXX - map options to config tree
        for k, v in self.opts.__dict__.iteritems():
            name, var = k.split('.')
            if name not in config:
                config[name] = {}
            config[name][var] = v

    def main(self, argv=sys.argv[1:], subclasses=None):
        """Run any Handler subclass in __main__ scope.
        """
        # XXX - even with only select enabled, BPF immediate doesn't
        # work on OSX, and we only get read events on full buffers.
        if sys.platform in ('darwin', 'win32'):
            os.putenv('EVENT_NOKQUEUE', '1')
            os.putenv('EVENT_NOPOLL', '1')

        if not subclasses:
            subclasses = find_subclasses(Handler, __import__('__main__'))
            if not subclasses:
                raise RuntimeError, 'no Handler subclasses found'

        event.init()
        self.setup()
        self.getopt(argv)

        # XXX - configure pcap filter
        global config
        config['pcap']['prefilter'] = ' '.join(self.args)

        for cls in subclasses:
            handlers[cls.name] = cls()
        for sig in (signal.SIGINT, signal.SIGTERM):
            event.signal(sig, event.abort)

        event.dispatch()

        for h in handlers.itervalues():
            h.teardown()
        self.teardown()

def main(argv=sys.argv[1:], profile=False):
    program = find_subclasses(Program, __import__('__main__'), [ Program ])[0]
    if profile:
        import hotshot, hotshot.stats
        filename = sys.argv[0] + '.prof'
        prof = hotshot.Profile(filename)
        prof.runcall(program().main, argv)
        stats = hotshot.stats.load(filename)
        stats.strip_dirs()
        stats.sort_stats('time', 'calls')
        stats.print_stats(20)
        os.unlink(filename)
    else:
        program().main(argv)

def test():
    import inspect
    subclasses = find_subclasses(Handler, __import__('__main__'))
    class TestHandler(Handler):
        def setup(self):
            for h in subclasses:
                for ev in h.events:
                    print 'SUBSCRIBE:', h.name, ev
                    self.subscribe(h.name, ev, self.output)

        def output(self, *args):
            f = inspect.currentframe(1)
            d = inspect.getargvalues(f)[3]
            print 'PUBLISH:', d['self'].name, d['event']
            print `args`

    subclasses.append(TestHandler)
    Program().main(argv=sys.argv[1:], subclasses=subclasses)
