"""hostwatch: host health, power, and crash monitoring."""

import logging

__version__ = "0.1.0"

# httpx writes one INFO line per request, which is one line per delivery and per collector read.
# Every entry point logs at INFO, so those lines are held back to WARNING here, for all of them.
for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).setLevel(logging.WARNING)
