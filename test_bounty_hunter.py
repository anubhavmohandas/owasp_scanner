#!/usr/bin/env python3
"""
Test script for Bug Bounty Hunter
Validates all functionality before running on real targets
"""

import sys
import os
import subprocess
import requests

def print_test(name, status):
    """Print test result"""
    symbol = "✅" if status else "❌"
    print(f"{symbol} {name}")
    return status

def test_imports():
    """Test all required imports"""
    try:
        import requests
        import json
        import re
        import time
        import datetime
        from bs4 import BeautifulSoup
        from urllib.parse import urlparse, urljoin
        from concurrent.futures import ThreadPoolExecutor
        return print_test("Import dependencies", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Import dependencies", False)

def test_bounty_hunter_import():
    """Test bounty_hunter module"""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import bounty_hunter
        return print_test("Import bounty_hunter.py", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Import bounty_hunter.py", False)

def test_program_parser():
    """Test program parser"""
    try:
        import program_parser
        from program_parser import ProgramParser

        # Test text parsing
        test_text = """
        Test Program
        Low 0.1 - 3.9
        Medium 4.0 - 6.9
        High 7.0 - 8.9
        Critical 9.0 - 10.0
        Low $100
        Medium $500
        """

        program = ProgramParser.parse_text_program(test_text)
        assert 'rewards' in program
        return print_test("Program parser", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Program parser", False)

def test_reconnaissance():
    """Test reconnaissance engine"""
    try:
        from bounty_hunter import ReconnaissanceEngine

        recon = ReconnaissanceEngine("https://example.com", verbose=False)
        assert recon.target_url == "https://example.com"
        return print_test("Reconnaissance engine", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Reconnaissance engine", False)

def test_directory_enumerator():
    """Test directory enumerator"""
    try:
        from bounty_hunter import DirectoryEnumerator

        enum = DirectoryEnumerator("https://example.com", threads=5)
        assert len(enum.wordlist) > 0
        return print_test("Directory enumerator", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Directory enumerator", False)

def test_report_generator():
    """Test report generator"""
    try:
        from bounty_hunter import BugBountyReportGenerator, BugBountyProgram

        program = BugBountyProgram(name="Test Program")
        vulns = [{
            'type': 'Test Vulnerability',
            'risk_level': 'High',
            'description': 'Test description',
            'location': 'https://example.com',
            'recommendation': 'Fix it',
            'cvss_score': 7.5
        }]

        report = BugBountyReportGenerator.generate_submission_report(
            vulns, program, "https://example.com", {}
        )
        assert "Test Vulnerability" in report
        return print_test("Report generator", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Report generator", False)

def test_cli_help():
    """Test CLI help command"""
    try:
        result = subprocess.run(
            ['python3', 'bounty_hunter.py', '--help'],
            capture_output=True,
            text=True,
            timeout=5
        )
        assert result.returncode == 0
        assert "Bug Bounty Hunter" in result.stdout
        return print_test("CLI help command", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("CLI help command", False)

def test_example_files():
    """Test example program files exist"""
    try:
        assert os.path.exists('examples/generic_program.txt')
        assert os.path.exists('examples/game_security_program.txt')
        return print_test("Example files present", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Example files present", False)

def test_network_connectivity():
    """Test basic network connectivity"""
    try:
        response = requests.get("https://example.com", timeout=5)
        assert response.status_code == 200
        return print_test("Network connectivity", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Network connectivity", False)

def test_quick_scan():
    """Test quick reconnaissance scan"""
    try:
        result = subprocess.run(
            ['python3', 'bounty_hunter.py', 'https://example.com',
             '--recon', '--no-banner'],
            capture_output=True,
            text=True,
            timeout=30
        )
        assert result.returncode == 0
        assert "Reconnaissance" in result.stdout
        return print_test("Quick recon scan", True)
    except Exception as e:
        print(f"  Error: {e}")
        return print_test("Quick recon scan", False)

def main():
    """Run all tests"""
    print("="*70)
    print("BUG BOUNTY HUNTER - VALIDATION TESTS")
    print("="*70)
    print()

    tests = [
        test_imports,
        test_bounty_hunter_import,
        test_program_parser,
        test_reconnaissance,
        test_directory_enumerator,
        test_report_generator,
        test_cli_help,
        test_example_files,
        test_network_connectivity,
        test_quick_scan
    ]

    passed = 0
    failed = 0

    for test in tests:
        if test():
            passed += 1
        else:
            failed += 1

    print()
    print("="*70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("="*70)

    if failed == 0:
        print("\n✅ All tests passed! Tool is ready to use.")
        return 0
    else:
        print(f"\n❌ {failed} test(s) failed. Please fix issues before using.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
