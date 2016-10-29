"""
Definitions for working with patterns from the Noise Protocol Framework.

Authors:
    Rhys Weatherley <rhys.weatherley@gmail.com>

This script is placed into the public domain.
"""

import sys
import re

__all__ = [
    'Pattern', 'PatternErrorReporter', 'PatternTokenizer',
    'PatternParser', 'loadPatterns'
]

NoiseParameters = ['e', 're', 's', 'rs', 'f', 'rf']
NoiseTokens = ['e', 's', 'ee', 'es', 'se', 'ss', 'f', 'ff']
NoisePremessageTokens = ['e', 's', 'f']

class Pattern:
    """
    Information about a Noise pattern.

    The 'name' property is the fully-qualified name of the pattern
    including transformations; e.g. "XXfallback+hfs".

    The 'parameters' property is a list of strings for the parameters
    to the pattern; e.g. ['s', 'rs'].

    The 'initiator_premessage' property is a list of tokens for the
    initiator's premessage; e.g. ['s'].

    The 'responder_premessage' property is a list of tokens for the
    responder's premessage; e.g. ['e'].

    The 'messages' property is a list of tuples for the messages in
    the pattern; e.g. XX is [('->', ['e']), ('<-', ['e', 'ee', 's', 'es']),
    ('->', ['s', 'se'])]

    The 'line' property is the line number in the file where the
    pattern was read from, or zero if the line number is unknown.

    The 'reporter' property is the error reporting object for the
    file the pattern was read from, for reporting errors and warnings
    in the pattern after syntactic analysis is finished.
    """
    name = ''
    parameters = []
    initiator_premessage = []
    responder_premessage = []
    messages = []
    line = 0
    reporter = None

    def isOneWay(self):
        """
        Determine if this is a one-way pattern; that is, there is only a
        single message in the body of the pattern.
        """
        return len(self.messages) == 1

    def isInteractive(self):
        """
        Determine if this is an interactive pattern; that is, there are
        multiple messages in the body of the pattern.
        """
        return len(self.messages) >= 2

    def baseName(self):
        """
        Returns the base name of the pattern without transformations.
        """
        m = re.match('([A-Z]+)', self.name)
        if m:
            return m.group(1)
        else:
            return None

    def transformations(self):
        """
        Returns the list of transformations that have been applied
        to the base name of the pattern.
        """
        m = re.match('([A-Z]+)([a-z].*)$', self.name)
        if m:
            return m.group(2).split('+')
        else:
            return []

    def addTransformation(self, t):
        """
        Adds a transformation to the name of this pattern.

        This is typically used when constructing a new pattern as a
        transformed variation on a pre-existing pattern.
        """
        ts = self.transformations()
        ts.append(t)
        self.name = self.baseName() + '+'.join(ts)

    def __str__(self):
        """
        Converts this pattern into its string representation in the
        formal Noise pattern syntax.
        """
        s = "Noise_" + self.name + "("
        if self.parameters:
            s += ", ".join(self.parameters)
        s += "):"
        if self.initiator_premessage:
            s += "\n   -> " + ", ".join(self.initiator_premessage)
            if self.responder_premessage:
                s += "\n   <- " + ", ".join(self.responder_premessage)
            s += "\n   ..."
        elif self.responder_premessage:
            s += "\n   <- " + ", ".join(self.responder_premessage)
            s += "\n   ..."
        for marker, tokens in self.messages:
            s += "\n   " + marker + " " + ", ".join(tokens)
        return s + "\n"

    def error(self, message):
        """
        Reports an error message for the pattern with the pattern's
        original line number and filename.
        """
        if reporter:
            reporter.error(line, message)
        elif line:
            sys.stderr.write(str(line) + ": " + str(message) + "\n")
        else:
            sys.stderr.write(str(message) + "\n")

    def warning(self, message):
        """
        Reports a warning message for the pattern with the pattern's
        original line number and filename.
        """
        if reporter:
            reporter.warning(line, message)
        elif line:
            sys.stderr.write(str(line) + ": warning: " + str(message) + "\n")
        else:
            sys.stderr.write("warning: " + str(message) + "\n")

class PatternErrorReporter:
    """
    Reports errors and warnings while processing patterns from an input stream.
    """

    def __init__(self, filename):
        """
        Constructs an error reporter for reporting problem
        in a specific file.
        """
        self._filename = filename
        self._errors = 0
        self._warnings = 0

    def line(self):
        """
        Gets the current line being parsed.
        """
        return self._linenum

    def error(self, line, message):
        """
        Reports an error message on a specific line of the input.
        """
        sys.stderr.write(str(self._filename) + ":" + str(line) + ": " + str(message) + "\n")
        self._errors += 1

    def warning(self, line, message):
        """
        Reports a warning message on a specific line of the input.
        """
        sys.stderr.write(str(self._filename) + ":" + str(line) + ": warning: " + str(message) + "\n")
        self._warnings += 1

    def hasErrors(self):
        """
        Determine if we encountered errors while processing the input.
        """
        return self._errors != 0

    def hasWarnings(self):
        """
        Determine if we encountered warnings while processing the input.
        """
        return self._warnings != 0

    def errorCount(self):
        """
        Returns the number of errors that have occurred so far.
        """
        return self._errors

    def warningCount(self):
        """
        Returns the number of warnings that have occurred so far.
        """
        return self._warnings

class PatternTokenizer:
    """
    Tokenizes Noise pattern definitions.
    """

    def __init__(self, stream, reporter):
        """
        Constructs a new pattern tokenizer from the contents of an input stream.
        """
        self._reporter = reporter
        self._lines = stream.readlines()
        self._token = None
        self._tokens = []
        self._line = 0
        self._scanner = re.Scanner([
            (r"\bNoise_[A-Za-z0-9]+(\+[A-Za-z0-9]+)*\b", lambda scanner,token:token),
            (r"\be\b",      lambda scanner,token:"e"),
            (r"\bee\b",     lambda scanner,token:"ee"),
            (r"\bes\b",     lambda scanner,token:"es"),
            (r"\bs\b",      lambda scanner,token:"s"),
            (r"\bse\b",     lambda scanner,token:"se"),
            (r"\bss\b",     lambda scanner,token:"ss"),
            (r"\bf\b",      lambda scanner,token:"f"),
            (r"\bff\b",     lambda scanner,token:"ff"),
            (r"\bre\b",     lambda scanner,token:"re"),
            (r"\brs\b",     lambda scanner,token:"rs"),
            (r"\brf\b",     lambda scanner,token:"rf"),
            (r"<-",         lambda scanner,token:"<-"),
            (r"->",         lambda scanner,token:"->"),
            (r"\.\.\.",     lambda scanner,token:"..."),
            (r"[,():]",     lambda scanner,token:token),
            (r"//[^\n]*\n", None),
            (r"\s+",        None),
        ])

    def token(self):
        """
        Gets the current token from the input stream.
        """
        return self._token

    def line(self):
        """
        Gets the line number of the current token.
        """
        return self._line

    def nextToken(self):
        """
        Reads the next token from the input stream.  Returns True
        if the next token is available or False at EOF.
        """
        if self._token == 'eof':
            return False
        while not self._tokens:
            if not self._lines:
                self._token = 'eof'
                return False
            self._line += 1
            self._tokens, rest = self._scanner.scan(self._lines.pop(0))
            if rest:
                self._reporter.error(self._line, "invalid token encountered at " + rest.strip())
        self._token = self._tokens.pop(0)
        return True

    def reporter(self):
        """
        Returns the error reporter that is being used by this tokenizer.
        """
        return self._reporter

class PatternParser:
    """
    Parses Noise pattern definitions from an input stream.
    """

    def __init__(self, stream, filename):
        """
        Constructs a new pattern parser.
        """
        self._reporter = PatternErrorReporter(filename)
        self._tokenizer = PatternTokenizer(stream, self._reporter)
        self._tokenizer.nextToken()
        self._resync(True)

    def _resync(self, report):
        """
        Re-synchronizes the input stream on the start of the next pattern
        when an error occurs.
        """
        while self._tokenizer.token() != 'eof' and not self._tokenizer.token().startswith('Noise_'):
            if report:
                self._reporter.error(self._tokenizer.line(), "unexpected token '" + self._tokenizer.token() + "', resynchronizing")
                report = False
            self._tokenizer.nextToken()

    def _expect(self, tokens):
        """
        Expects one of a number of tokens to occur next and then skips it.
        Reports an error if not.  Returns the token that was actually found
        or None.
        """
        token = self._tokenizer.token()
        if type(tokens) is list:
            # Expecting one of a number of tokens in a list.
            if token in tokens:
                self._tokenizer.nextToken()
                return token
            else:
                msg = "one of '" + "', '".join(tokens) + "' expected"
                self._reporter.error(self._tokenizer.line(), msg)
                return None
        else:
            # Expecting a specific token.
            if token == tokens:
                self._tokenizer.nextToken()
                return token
            else:
                self._reporter.error(self._tokenizer.line(), "'" + str(tokens) + "') expected")
                return None

    def _peek(self, tokens):
        """
        Same as _expect(), but does not skip the token if it matches or
        report an error if it doesn't match.
        """
        token = self._tokenizer.token()
        if type(tokens) is list:
            # Expecting one of a number of tokens in a list.
            if token in tokens:
                return token
            else:
                return None
        else:
            # Expecting a specific token.
            if token == tokens:
                return token
            else:
                return None

    def _parseMessage(self, messages, initiator):
        """
        Parses a token list starting with '->' or '<-'.
        """
        if initiator:
            if not self._expect('->'):
                return False
            marker = '->'
        else:
            if not self._expect('<-'):
                return False
            marker = '<-'
        if not self._tokenizer.token() in NoiseTokens:
            self._reporter.error(self._tokenizer.line(), "message token expected")
            return False
        msgs = []
        msgs.append(self._tokenizer.token())
        self._tokenizer.nextToken()
        while self._tokenizer.token() == ',':
            self._tokenizer.nextToken()
            if not self._tokenizer.token() in NoiseTokens:
                self._reporter.error(self._tokenizer.line(), "message token expected after comma")
                return False
            msgs.append(self._tokenizer.token())
            self._tokenizer.nextToken()
        messages.append((marker, msgs))
        return True

    def _setPreMessages(self, pattern, messages):
        """
        Sets the pre-messages for a pattern and validates them.
        """
        if not messages:
            self._reporter.error(self._tokenizer.line(), "pre-message is empty")
            return False
        for marker, msgs in messages:
            for token in msgs:
                if not token in NoisePremessageTokens:
                    self._reporter.error(self._tokenizer.line(), "'" + token + "' is not a valid pre-message token")
                    return False
            if marker == '->':
                if pattern.initiator_premessage:
                    self._reporter.error(self._tokenizer.line(), "multiple initiator pre-messages")
                    return False
                pattern.initiator_premessage = msgs
            else:
                if pattern.responder_premessage:
                    self._reporter.error(self._tokenizer.line(), "multiple responder pre-messages")
                    return False
                pattern.responder_premessage = msgs
        return True

    def _parsePattern(self, pattern):
        """
        Parses a pattern from the input stream, starting at a name token.
        """
        pattern.name = self._tokenizer.token()[6:]
        pattern.line = self._tokenizer.line()
        pattern.reporter = self._reporter
        self._tokenizer.nextToken()

        # Parse the parameter list
        if not self._expect('('):
            return
        pattern.parameters = []
        while self._peek(NoiseParameters):
            pattern.parameters.append(self._tokenizer.token())
            self._tokenizer.nextToken()
            if not self._peek(','):
                break
            self._tokenizer.nextToken()
        if not self._expect(')'):
            return
        if not self._expect(':'):
            return

        messages = []
        if self._peek('<-'):
            # Must be a pre-message, because message bodies always start with '->'.
            if not self._parseMessage(messages, False):
                return
            if not self._peek('...'):
                self._reporter.error(self._tokenizer.line(), "invalid pre-message")
                return
        else:
            initiator = True
            while self._peek(['->', '<-']):
                if not self._parseMessage(messages, initiator):
                    return
                initiator = not initiator

        if self._peek('...'):
            # The previous sequences were pre-messages - validate them.
            if not self._setPreMessages(pattern, messages):
                return

            # Now parse the actual message body.
            self._tokenizer.nextToken()
            messages = []
            initiator = True
            while self._peek(['->', '<-']):
                if not self._parseMessage(messages, initiator):
                    return
                initiator = not initiator

        if not messages:
            self._reporter.error(self._tokenizer.line(), "message body is empty")
            return
        pattern.messages = messages

    def readPattern(self):
        """
        Reads the next pattern from the input stream and returns it.
        Returns None at the end of the input stream.
        """
        report = True
        while self._tokenizer.token() != 'eof':
            self._resync(report)
            report = False
            if self._tokenizer.token().startswith('Noise_'):
                prevErrorCount = self._reporter.errorCount()
                pattern = Pattern()
                self._parsePattern(pattern)
                if self._reporter.errorCount() == prevErrorCount:
                    # No errors reported, so the pattern is ok.
                    return pattern
        return None

    def readPatterns(self):
        """
        Returns a list of all patterns in the input stream.
        """
        patterns = []
        while self._tokenizer.token != 'eof':
            pattern = self.readPattern()
            if not pattern:
                break
            patterns.append(pattern)
        return patterns

    def reporter(self):
        """
        Returns the error reporter that is being used by this parser.
        """
        return self._reporter

def loadPatterns(filename):
    """
    Helper function that loads all Noise patterns from a file.
    """
    if filename == "-":
        parser = PatternParser(sys.stdin, "stdin")
    else:
        with open(filename) as file:
            parser = PatternParser(file, filename)
    return parser.readPatterns()
