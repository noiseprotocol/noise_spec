#!/usr/bin/python
"""
Applies the 'fallback' transformation to Noise patterns.

Authors:
    Rhys Weatherley <rhys.weatherley@gmail.com>

This script is placed into the public domain.
"""

import sys
from noise_patterns import *

def combine(list1, list2):
    result = list(list1)
    for elem in list2:
        if not elem in list1:
            result.append(elem)
    return result

def make_fallback(orig):
    pattern = Pattern()
    pattern.name = orig.name
    pattern.addTransformation('fallback')
    direction, first_message = orig.messages[0]
    pattern.parameters = combine(first_message, orig.parameters)
    pattern.initiator_premessage = first_message + orig.initiator_premessage
    pattern.responder_premessage = list(orig.responder_premessage)
    pattern.messages = []
    for direction, message in orig.messages[1:]:
        pattern.messages.append((direction, list(message)))
    return pattern

def fallback_compatible(pattern):
    direction, messages = pattern.messages[0];
    if direction != '->':
        return False
    if messages == ['e'] or messages == ['e', 's']:
        return True
    return False

if len(sys.argv) <= 1:
    print "Usage: " + sys.argv[0] + " file ..."
    sys.exit(1)

for file in sys.argv[1:]:
    patterns = loadPatterns(file)
    for pattern in patterns:
        if not pattern.isInteractive():
            # Only interactive patterns can be fallback.
            continue
        if 'fallback' in pattern.transformations():
            # The pattern is already fallback.
            continue
        if not fallback_compatible(pattern):
            # The first message is not fallback-compatible.
            continue
        fallback = make_fallback(pattern)
        print fallback

sys.exit(0)
