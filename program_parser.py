#!/usr/bin/env python3
"""
Bug Bounty Program Parser
Parse bug bounty programs from Intigriti, HackerOne, Bugcrowd, etc.
"""

import requests
import re
import json
from typing import Dict, List, Optional
from bs4 import BeautifulSoup


class ProgramParser:
    """Parse bug bounty program details from various platforms"""

    @staticmethod
    def parse_intigriti_url(url: str) -> Dict:
        """Parse Intigriti program URL"""
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')

            program_data = {
                'platform': 'Intigriti',
                'name': '',
                'scope': [],
                'out_of_scope': [],
                'rewards': {},
                'description': ''
            }

            # Extract program name from title
            title = soup.find('title')
            if title:
                program_data['name'] = title.text.strip()

            # Extract description
            description_div = soup.find('div', class_='description') or soup.find('div', id='program-description')
            if description_div:
                program_data['description'] = description_div.get_text().strip()

            # Try to extract scope
            scope_section = soup.find(text=re.compile('In scope', re.I))
            if scope_section:
                scope_parent = scope_section.find_parent()
                if scope_parent:
                    scope_items = scope_parent.find_all(['li', 'p'])
                    program_data['scope'] = [item.get_text().strip() for item in scope_items]

            # Extract rewards
            reward_table = soup.find('table') or soup.find(text=re.compile('Bounties', re.I))
            if reward_table:
                # Parse reward tiers
                severity_pattern = r'(Critical|High|Medium|Low|Info)\s*[:\-]?\s*€?(\d+[\d,]*)'
                matches = re.findall(severity_pattern, response.text, re.IGNORECASE)
                for severity, amount in matches:
                    program_data['rewards'][severity.lower()] = amount.replace(',', '')

            return program_data

        except Exception as e:
            print(f"Error parsing Intigriti program: {e}")
            return {}

    @staticmethod
    def parse_text_program(text: str) -> Dict:
        """Parse program details from text description"""
        program_data = {
            'platform': 'Custom',
            'name': '',
            'scope': [],
            'out_of_scope': [],
            'rewards': {},
            'description': text,
            'cvss_mapping': {}
        }

        # Extract program name
        name_patterns = [
            r'([\w\s]+(?:Program|Security|Bug Bounty))',
            r'Program:\s*([^\n]+)',
            r'Platform:\s*([^\n]+)'
        ]
        for pattern in name_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                program_data['name'] = match.group(1).strip()
                break

        # Extract CVSS to severity mapping
        cvss_pattern = r'(Low|Medium|High|Critical|Exceptional)\s*(\d+\.?\d*)\s*-\s*(\d+\.?\d*)'
        for match in re.finditer(cvss_pattern, text, re.IGNORECASE):
            severity = match.group(1).lower()
            min_score = float(match.group(2))
            max_score = float(match.group(3))
            program_data['cvss_mapping'][severity] = {
                'min': min_score,
                'max': max_score
            }

        # Extract monetary rewards
        # Pattern: Low/Medium/High/Critical followed by currency amount
        reward_patterns = [
            r'(Low|Medium|High|Critical|Exceptional)\s*€\s*(\d+[\d,]*)',
            r'(Low|Medium|High|Critical|Exceptional)\s*\$\s*(\d+[\d,]*)',
            r'Tier\s*\d+\s*(Low|Medium|High|Critical)\s*€\s*(\d+[\d,]*)'
        ]

        for pattern in reward_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                severity = match.group(1).lower()
                amount = match.group(2).replace(',', '')
                program_data['rewards'][severity] = amount

        # Extract scope
        scope_section = re.search(r'(?:In[\s-]?Scope|Scope):(.+?)(?:Out[\s-]?of[\s-]?Scope|Prohibited|$)',
                                 text, re.DOTALL | re.IGNORECASE)
        if scope_section:
            scope_text = scope_section.group(1)
            # Extract URLs and domains
            urls = re.findall(r'https?://[^\s\)]+', scope_text)
            domains = re.findall(r'[\w-]+\.[\w.-]+', scope_text)
            program_data['scope'] = list(set(urls + domains))

        # Extract out of scope
        out_scope_section = re.search(r'(?:Out[\s-]?of[\s-]?Scope|Prohibited):(.+?)(?:$|\n\n)',
                                      text, re.DOTALL | re.IGNORECASE)
        if out_scope_section:
            out_text = out_scope_section.group(1)
            out_items = re.findall(r'[•\-\*]\s*([^\n]+)', out_text)
            program_data['out_of_scope'] = [item.strip() for item in out_items]

        return program_data

    @staticmethod
    def get_severity_for_cvss(cvss_score: float, cvss_mapping: Dict) -> str:
        """Get severity level based on CVSS score and program mapping"""
        for severity, score_range in cvss_mapping.items():
            if score_range['min'] <= cvss_score <= score_range['max']:
                return severity.capitalize()

        # Default CVSS mapping if none provided
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"

    @staticmethod
    def estimate_bounty(severity: str, rewards: Dict) -> str:
        """Estimate bounty amount for severity"""
        severity_lower = severity.lower()
        if severity_lower in rewards:
            return f"€{rewards[severity_lower]}"
        return "Not specified"

    @staticmethod
    def save_program(program_data: Dict, filename: str):
        """Save program data to JSON file"""
        with open(filename, 'w') as f:
            json.dump(program_data, f, indent=2)
        print(f"✅ Program data saved to {filename}")

    @staticmethod
    def load_program(filename: str) -> Dict:
        """Load program data from JSON file"""
        with open(filename, 'r') as f:
            return json.load(f)


def main():
    """Main program parser function"""
    import argparse

    parser = argparse.ArgumentParser(description='Parse Bug Bounty Program Details')
    parser.add_argument('--url', help='Intigriti program URL')
    parser.add_argument('--file', help='Text file containing program details')
    parser.add_argument('--text', help='Program description text')
    parser.add_argument('--output', help='Output JSON file', default='program.json')

    args = parser.parse_args()

    program_data = {}

    if args.url:
        print(f"📡 Parsing Intigriti program: {args.url}")
        program_data = ProgramParser.parse_intigriti_url(args.url)
    elif args.file:
        print(f"📄 Parsing program from file: {args.file}")
        with open(args.file, 'r') as f:
            program_data = ProgramParser.parse_text_program(f.read())
    elif args.text:
        print("📝 Parsing program from text")
        program_data = ProgramParser.parse_text_program(args.text)
    else:
        print("❌ Please provide --url, --file, or --text")
        return

    # Display parsed data
    print("\n" + "="*70)
    print("PROGRAM DETAILS")
    print("="*70)
    print(f"Name: {program_data.get('name', 'N/A')}")
    print(f"Platform: {program_data.get('platform', 'N/A')}")
    print(f"\nScope items: {len(program_data.get('scope', []))}")
    print(f"Reward tiers: {len(program_data.get('rewards', {}))}")

    if program_data.get('rewards'):
        print("\n Rewards:")
        for severity, amount in program_data['rewards'].items():
            print(f"  {severity.capitalize()}: €{amount}")

    # Save to file
    ProgramParser.save_program(program_data, args.output)


if __name__ == "__main__":
    main()
