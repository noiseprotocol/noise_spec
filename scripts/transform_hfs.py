#!/usr/bin/python
"""
Applies the 'hfs' transformation to Noise patterns.

Authors:
    Rhys Weatherley <rhys.weatherley@gmail.com>

This script is placed into the public domain.
"""

import sys
from noise_patterns import *

def hybridize(tokens):
    result = []
    for token in tokens:
        result.append(token)
        if token == 'e':
            result.append('f')
        elif token == 'ee':
            result.append('ff')
        elif token == 're':
            result.append('rf')
    return result

def make_hfs(orig):
    pattern = Pattern()
    pattern.name = orig.name
    pattern.addTransformation('hfs')
    pattern.parameters = hybridize(orig.parameters)
    pattern.initiator_premessage = hybridize(orig.initiator_premessage)
    pattern.responder_premessage = hybridize(orig.responder_premessage)
    pattern.messages = []
    for marker, tokens in orig.messages:
        pattern.messages.append((marker, hybridize(tokens)))
    return pattern

if len(sys.argv) <= 1:
    print "Usage: " + sys.argv[0] + " file ..."
    sys.exit(1)

for file in sys.argv[1:]:
    patterns = loadPatterns(file)
    for pattern in patterns:
        if not pattern.isInteractive():
            # Only interactive patterns can by hybridized.
            continue
        if 'hfs' in pattern.transformations():
            # The pattern is already hybrid.
            continue
        hfs = make_hfs(pattern)
        print hfs

sys.exit(0)
