# $Id$

import cStringIO, htmlentitydefs, re
from xml.sax.saxutils import unescape as __unescape

__tag_re = re.compile("</?[a-z0-9A-Z]+.*?>|<!.*?-->", re.M|re.S)

def strip(s):
    return __unescape(__tag_re.sub('', s))

# From Ka-Ping Yee
def decode(text):
    """Decode HTML entities in the given text."""
    chunks = text.split('&')
    for i in range(1, len(chunks)):
        if ';' in chunks[i][:10]:
            entity, rest = chunks[i].split(';', 1)
            if entity.startswith('#'):
                chunks[i] = chr(int(entity[1:])) + rest
            elif entity in htmlentitydefs.entitydefs:
                chunks[i] = htmlentitydefs.entitydefs[entity] + rest
            else:
                chunks[i] = '&' + chunks[i]
        else:
            chunks[i] = '&' + chunks[i]
    return ''.join(chunks)

