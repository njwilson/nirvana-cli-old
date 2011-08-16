#!/usr/bin/env python

import logging

# Get NullHandler. Only added to the standard library since Python 2.7.
try:
    __pychecker__ = 'no-miximport'
    from logging import NullHandler
    __pychecker__ = ''
except ImportError:
    class NullHandler(logging.Handler):
        """Do-nothing handler for log messages."""
        def emit(self, record):
            """Silently ignore the message."""
            pass


# Make sure "nirvana" has a log handler to avoid this message when the
# library is used: 'No handlers could be found for logger "nirvana"'
log = logging.getLogger('nirvana')
if not log.handlers:
    log.addHandler(NullHandler())
