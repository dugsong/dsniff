# $Id$

BLACK, RED = range(2)
LEFT, RIGHT, PARENT = range(3)

class _ItreeNode(object):
    __slots__ = ('low', 'high', 'data', 'max', 'color', 'kids', 'parent')
    def __init__(self, low, high, data):
        self.low, self.high, self.data = low, high, data
        self.max = high
        self.color = RED
        self.kids = [ None, None ]
        self.parent = None

class Itree(object):
    """Simple interval tree.
    """
    def __init__(self):
        self.root = None
        self.count = 0

    def __max_fixup(self, elm):
        elm.max = elm.high
        for i in range(2):
            if elm.kids[i] and elm.kids[i].max > elm.max:
                elm.max = elm.kids[i].max

    def __rotate(self, elm, n):
        tmp = elm.kids[n ^ 1]
        elm.kids[n ^ 1] = tmp.kids[n]
        if elm.kids[n ^ 1]:
            tmp.kids[n].parent = elm
        tmp.parent = elm.parent
        if tmp.parent:
            if elm == elm.parent.kids[n]:
                elm.parent.kids[n] = tmp
            else:
                elm.parent.kids[n ^ 1] = tmp
        else:
            self.root = tmp
        tmp.kids[n] = elm
        elm.parent = tmp

        self.__max_fixup(elm)
        self.__max_fixup(tmp)

    def add(self, low, high, item):
        """Add interval with item to be returned on match.
        """
        elm = _ItreeNode(low, high, item)
        parent, tmp = None, self.root
        while tmp:
            parent = tmp
            if tmp.max < elm.max:
                tmp.max = elm.max
            tmp = tmp.kids[int(elm.low >= tmp.low)]
        if parent:
            parent.kids[int(elm.low >= parent.low)] = elm
            elm.parent = parent
        else:
            self.root = elm
        self.count += 1

        # rebalance and color
        parent = elm.parent
        while parent and parent.color == RED:
            gparent = parent.parent
            n = int(parent != gparent.kids[LEFT])
            tmp = gparent.kids[n ^ 1]
            if tmp and tmp.color == RED:
                tmp.color, parent.color, gparent.color = BLACK, BLACK, RED
                elm = gparent
            else:
                if parent.kids[n ^ 1] == elm:
                    self.__rotate(parent, n)
                    tmp, parent, elm = parent, elm, tmp
                parent.color, gparent.color = BLACK, RED
                self.__rotate(gparent, n ^ 1)
        self.root.color = BLACK

    def __match(self, elm, low, high, matches):
        if not elm:
            return
        if low <= elm.high and elm.low <= high:
            matches.append(elm.data)
        if elm.kids[LEFT] and low <= elm.kids[LEFT].max:
            self.__match(elm.kids[LEFT], low, high, matches)
        if elm.kids[RIGHT] and high >= elm.low and low <= elm.kids[RIGHT].max:
            self.__match(elm.kids[RIGHT], low, high, matches)

    def match(self, low, high=None):
        """Perform stabbing query for all overlapping intervals
        returning a list of matched items.
        """
        if high is None:
            high = low
        elm = self.root
        matches = []
        self.__match(elm, low, high, matches)
        return matches

    def __len__(self):
        return self.count

if __name__ == '__main__':
    import unittest
    import dnet

    class ItreeTestCase(unittest.TestCase):
        def test_itree(self):
            it = Itree()
            it.add(0, 10, 'dec')
            it.add(0, 16, 'hex')
            it.add(0, 8, 'oct')
            it.add('a', 'f', 'a-f')
            a = dnet.addr('10.0.0.0/8')
            it.add(a.net(), a.bcast(), '10/8')
            assert it.match(-5, -5) == it.match(33, 33) == []
            assert it.match(-10, 0) == ['hex', 'dec', 'oct']
            assert it.match(5, 8) == ['hex', 'dec', 'oct']
            assert it.match(9, 10) == ['hex', 'dec']
            assert it.match(16, 23) == ['hex']
            assert it.match('c') == ['a-f']
            assert it.match('b0rked', 'dugsong') == ['a-f']
            assert it.match('z') == []
            assert it.match(dnet.addr('10.0.0.1')) == ['10/8']
            assert it.match(dnet.addr('10.0.0.0'), dnet.addr('10.255.255.255')) == ['10/8']
            assert it.match(dnet.addr('10.0.1.0'), dnet.addr('10.0.1.255')) == ['10/8']
            assert it.match(dnet.addr('1.0.0.10')) == []

    unittest.main()
