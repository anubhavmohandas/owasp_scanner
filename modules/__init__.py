"""
OWASP Scanner Modules

This package contains specialized vulnerability scanners for various
OWASP Top 10 security vulnerabilities.
"""

from .broken_access_control import BrokenAccessControlScanner
from .cryptographic_failures import CryptographicFailuresScanner
from .injection import InjectionScanner
from .security_misconfiguration import SecurityMisconfigurationScanner

__all__ = [
    'BrokenAccessControlScanner',
    'CryptographicFailuresScanner',
    'InjectionScanner',
    'SecurityMisconfigurationScanner'
]
__version__ = '2.0.0'
