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
from .insecure_design import InsecureDesignScanner
from .authentication_failures import AuthenticationFailuresScanner
from .data_integrity_failures import DataIntegrityFailuresScanner
from .logging_monitoring_failures import LoggingMonitoringFailuresScanner
from .exceptional_conditions import ExceptionalConditionsScanner

__all__ = [
    'BrokenAccessControlScanner',
    'SecurityMisconfigurationScanner',
    'SupplyChainFailuresScanner',
    'CryptographicFailuresScanner',
    'InjectionScanner',
    'InsecureDesignScanner',
    'AuthenticationFailuresScanner',
    'DataIntegrityFailuresScanner',
    'LoggingMonitoringFailuresScanner',
    'ExceptionalConditionsScanner'
]
__version__ = '3.0.0'  # Complete OWASP Top 10:2025 support (all 10 categories)
