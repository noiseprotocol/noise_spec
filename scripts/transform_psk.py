#!/usr/bin/python
"""
Applies the 'pskN' transformations to Noise patterns.

Authors:
    Rhys Weatherley <rhys.weatherley@gmail.com>

This script is placed into the public domain.
"""

import sys
from noise_patterns import *

def make_psk(orig, modifier, psk_num):
    pattern = Pattern()
    pattern.name = orig.name
    pattern.addTransformation(modifier)
    pattern.parameters = list(orig.parameters)
    pattern.initiator_premessage = list(orig.initiator_premessage)
    pattern.responder_premessage = list(orig.responder_premessage)
    pattern.messages = []
    if psk_num == 0:
        direction, message = orig.messages[0]
        pattern.messages.append((direction, ['psk'] + message))
        for direction, message in orig.messages[1:]:
            pattern.messages.append((direction, list(message)))
    else:
        posn = 1
        for direction, message in orig.messages:
            if psk_num == posn:
                pattern.messages.append((direction, message + ['psk']))
            else:
                pattern.messages.append((direction, list(message)))
            posn += 1
    return pattern

if len(sys.argv) <= 2:
    print "Usage: " + sys.argv[0] + " N file ..."
    sys.exit(1)

psk_num = int(sys.argv[1])
modifier = "psk" + sys.argv[1]

for file in sys.argv[2:]:
    patterns = loadPatterns(file)
    for pattern in patterns:
        if modifier in pattern.transformations():
            # The modifier was already applied to this pattern.
            continue
        if psk_num > len(pattern.messages):
            # Cannot apply the modifier to this pattern because
            # there aren't enough messages in it.
            continue
        psk = make_psk(pattern, modifier, psk_num)
        print psk

sys.exit(0)
