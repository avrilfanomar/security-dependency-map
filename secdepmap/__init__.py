"""secdepmap - security dependency map for a Linux host.

Builds a graph of *what software is on a machine*, *where it came from*,
*who vouches for it* (signing keys, store assertions, publishers) and
*which vendor security channels cover it*, then derives findings.

Standard library only. Python >= 3.8.
"""

__version__ = "0.1.0"
SCHEMA_VERSION = 1
