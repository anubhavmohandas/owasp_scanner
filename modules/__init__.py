"""
OWASP Scanner Modules

This package contains specialized vulnerability scanners for various
OWASP Top 10 security vulnerabilities.
"""

from .broken_access_control import BrokenAccessControlScanner
from .cryptographic_failures import CryptographicFailuresScanner
from .injection import InjectionScanner
from .security_misconfiguration import SecurityMisconfigurationScanner
from .supply_chain_failures import SupplyChainFailuresScanner
from .exceptional_conditions import ExceptionalConditionsScanner

__all__ = [
    'BrokenAccessControlScanner',
    'CryptographicFailuresScanner',
    'InjectionScanner',
    'SecurityMisconfigurationScanner',
    'SupplyChainFailuresScanner',
    'ExceptionalConditionsScanner'
]
__version__ = '2.1.0'  # Updated for OWASP Top 10:2025 support
