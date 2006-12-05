# $Id$

"""XXX quick JSON parser, based on Michael Spencer's safe eval().
should use simplejson instead...
"""

import compiler

class AbstractVisitor(object):
    def __init__(self):
        self._cache = {} # dispatch table

    def visit(self, node,**kw):
        cls = node.__class__
        meth = self._cache.setdefault(
            cls, getattr(self, 'visit' + cls.__name__, self.default))
        return meth(node, **kw)

    def default(self, node, **kw):
        for child in node.getChildNodes():
            return self.visit(child, **kw)
    visitExpression = default

class SafeEval(AbstractVisitor):
    def visitConst(self, node, **kw):
        return node.value

    def visitDict(self, node, **kw):
        return dict([ (self.visit(k), self.visit(v)) for k,v in node.items ])

    def visitTuple(self, node, **kw):
        return tuple([ self.visit(i) for i in node.nodes ])

    def visitList(self, node, **kw):
        return [ self.visit(i) for i in node.nodes ]

def parse(s):
    try:
        ast = compiler.parse(s, 'eval')
    except SyntaxError, err:
        raise
    try:
        return SafeEval().visit(ast)
    except ValueError, err:
        raise

