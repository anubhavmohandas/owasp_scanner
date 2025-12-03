"""
OWASP Scanner Modules

This package contains specialized vulnerability scanners for various
OWASP Top 10 security vulnerabilities.
"""

from .broken_access_control import BrokenAccessControlScanner
from .cryptographic_failures import CryptographicFailuresScanner

__all__ = ['BrokenAccessControlScanner', 'CryptographicFailuresScanner']
__version__ = '1.0.0'
