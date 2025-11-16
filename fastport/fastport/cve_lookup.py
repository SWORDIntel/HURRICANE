#!/usr/bin/env python3
"""
CVE Vulnerability Lookup Module
Queries CVE databases for known vulnerabilities in detected services/technologies
Part of HDAIS audit pipeline
"""

import json
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import re


@dataclass
class CVERecord:
    """Represents a CVE vulnerability record"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    last_modified: str
    references: List[str] = field(default_factory=list)
    cpe_matches: List[str] = field(default_factory=list)
    is_rce: bool = False  # NEW: Flag for Remote Code Execution vulnerabilities
    attack_vector: str = ""  # NEW: Attack vector (NETWORK, LOCAL, etc.)
    exploit_available: bool = False  # NEW: Flag if known exploit exists


@dataclass
class ServiceVulnerability:
    """Represents vulnerabilities for a specific service"""
    service_name: str
    version: str
    cves: List[CVERecord] = field(default_factory=list)
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    rce_count: int = 0  # NEW: Count of RCE vulnerabilities
    network_exploitable_count: int = 0  # NEW: Count of network-exploitable vulns


def is_rce_vulnerability(description: str, cwe_ids: List[str] = None) -> bool:
    """
    Detect if a CVE is a Remote Code Execution vulnerability

    Args:
        description: CVE description text
        cwe_ids: List of CWE IDs associated with the CVE

    Returns:
        True if CVE appears to be an RCE vulnerability
    """
    if not description:
        return False

    desc_lower = description.lower()

    # RCE-related keywords and phrases
    rce_keywords = [
        'remote code execution',
        'execute arbitrary code',
        'arbitrary code execution',
        'code injection',
        'command injection',
        'rce',
        'execute code remotely',
        'allows remote attackers to execute',
        'allows attackers to execute arbitrary',
        'remote command execution',
        'arbitrary command execution',
        'execute system commands',
        'shell command',
        'exec(',
        'eval(',
        'deserialization'
    ]

    # Check for RCE keywords
    for keyword in rce_keywords:
        if keyword in desc_lower:
            return True

    # Check CWE IDs for RCE-related weaknesses
    if cwe_ids:
        rce_cwes = [
            'CWE-94',   # Code Injection
            'CWE-77',   # Command Injection
            'CWE-78',   # OS Command Injection
            'CWE-502',  # Deserialization of Untrusted Data
            'CWE-20',   # Improper Input Validation (sometimes leads to RCE)
        ]
        for cwe in cwe_ids:
            if any(rce_cwe in cwe for rce_cwe in rce_cwes):
                return True

    return False


class CVELookup:
    """CVE vulnerability lookup using multiple sources"""

    def __init__(self, api_key: Optional[str] = None, rate_limit: float = 0.6):
        """
        Initialize CVE lookup

        Args:
            api_key: Optional NVD API key for higher rate limits
            rate_limit: Seconds between requests (0.6s = 100 requests/minute for free tier)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.last_request_time = 0

        # NVD API endpoints
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        # Service name mappings (normalize names for better matching)
        self.service_mappings = {
            'WordPress': 'wordpress',
            'Drupal': 'drupal',
            'Django': 'django',
            'Flask': 'flask',
            'FastAPI': 'fastapi',
            'Ruby on Rails': 'ruby_on_rails',
            'React': 'react',
            'Angular': 'angular',
            'Vue.js': 'vue.js',
            'Kubernetes': 'kubernetes',
            'Docker': 'docker',
            'JupyterHub': 'jupyterhub',
            'TensorFlow': 'tensorflow',
            'PyTorch': 'pytorch',
            'MLflow': 'mlflow',
            'Airflow': 'apache_airflow',
            'Ray': 'ray',
            'nginx': 'nginx',
            'Apache': 'apache',
            'OpenSSH': 'openssh',
            'MySQL': 'mysql',
            'PostgreSQL': 'postgresql',
            'Redis': 'redis',
            'MongoDB': 'mongodb',
        }

    def _rate_limit_wait(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time

        if time_since_last_request < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last_request
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def _make_nvd_request(self, keyword: str, results_per_page: int = 20) -> Optional[Dict]:
        """
        Make a request to NVD API

        Args:
            keyword: Search keyword (service name)
            results_per_page: Number of results to fetch

        Returns:
            JSON response or None if failed
        """
        self._rate_limit_wait()

        params = {
            'keywordSearch': keyword,
            'resultsPerPage': results_per_page,
        }

        url = f"{self.nvd_base_url}?{urllib.parse.urlencode(params)}"

        headers = {
            'User-Agent': 'HDAIS-CVE-Lookup/1.0',
        }

        if self.api_key:
            headers['apiKey'] = self.api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"[!] API rate limit exceeded. Consider using an API key or increasing rate_limit.")
            elif e.code == 404:
                return None  # No results found
            else:
                print(f"[!] HTTP Error {e.code}: {e.reason}")
            return None
        except urllib.error.URLError as e:
            print(f"[!] URL Error: {e.reason}")
            return None
        except Exception as e:
            print(f"[!] Error querying NVD: {e}")
            return None

    def _parse_nvd_response(self, response: Dict) -> List[CVERecord]:
        """Parse NVD API response into CVERecord objects"""
        cve_records = []

        if not response or 'vulnerabilities' not in response:
            return cve_records

        for vuln in response['vulnerabilities']:
            try:
                cve_data = vuln['cve']
                cve_id = cve_data['id']

                # Get description
                description = ""
                if 'descriptions' in cve_data:
                    for desc in cve_data['descriptions']:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break

                # Get CVSS metrics and attack vector
                severity = "UNKNOWN"
                cvss_score = 0.0
                attack_vector = ""

                if 'metrics' in cve_data:
                    # Try CVSS v3.1 first, then v3.0, then v2.0
                    for metric_version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if metric_version in cve_data['metrics'] and cve_data['metrics'][metric_version]:
                            metric = cve_data['metrics'][metric_version][0]
                            if 'cvssData' in metric:
                                cvss_score = metric['cvssData'].get('baseScore', 0.0)
                                severity = metric['cvssData'].get('baseSeverity', 'UNKNOWN')
                                attack_vector = metric['cvssData'].get('attackVector', '')
                            elif 'baseSeverity' in metric:
                                severity = metric['baseSeverity']
                                cvss_score = metric.get('baseScore', 0.0)
                            break

                # Get CWE IDs for RCE detection
                cwe_ids = []
                if 'weaknesses' in cve_data:
                    for weakness in cve_data['weaknesses']:
                        if 'description' in weakness:
                            for desc in weakness['description']:
                                if 'value' in desc:
                                    cwe_ids.append(desc['value'])

                # Get references and check for exploit availability
                references = []
                exploit_available = False
                if 'references' in cve_data:
                    for ref in cve_data['references'][:5]:
                        ref_url = ref.get('url', '')
                        references.append(ref_url)
                        # Check if reference contains exploit indicators
                        if any(exploit_keyword in ref_url.lower() for exploit_keyword in ['exploit', 'poc', 'metasploit', 'github.com/exploit']):
                            exploit_available = True

                # Detect RCE vulnerability
                is_rce = is_rce_vulnerability(description, cwe_ids)

                # Get CPE matches
                cpe_matches = []
                if 'configurations' in cve_data:
                    for config in cve_data['configurations']:
                        if 'nodes' in config:
                            for node in config['nodes']:
                                if 'cpeMatch' in node:
                                    for cpe in node['cpeMatch'][:3]:
                                        if 'criteria' in cpe:
                                            cpe_matches.append(cpe['criteria'])

                published = cve_data.get('published', '')
                modified = cve_data.get('lastModified', '')

                cve_record = CVERecord(
                    cve_id=cve_id,
                    description=description[:500],  # Truncate long descriptions
                    severity=severity,
                    cvss_score=cvss_score,
                    published_date=published,
                    last_modified=modified,
                    references=references,
                    cpe_matches=cpe_matches,
                    is_rce=is_rce,
                    attack_vector=attack_vector,
                    exploit_available=exploit_available
                )

                cve_records.append(cve_record)

            except Exception as e:
                print(f"[!] Error parsing CVE record: {e}")
                continue

        return cve_records

    def lookup_service(self, service_name: str, version: Optional[str] = None) -> ServiceVulnerability:
        """
        Lookup CVEs for a specific service

        Args:
            service_name: Name of the service/technology
            version: Optional version string

        Returns:
            ServiceVulnerability object with CVE records
        """
        # Normalize service name
        normalized_name = self.service_mappings.get(service_name, service_name.lower())

        print(f"[*] Looking up CVEs for: {service_name}")

        # Query NVD
        response = self._make_nvd_request(normalized_name, results_per_page=20)

        cve_records = []
        if response:
            cve_records = self._parse_nvd_response(response)

        # Count by severity
        critical = sum(1 for c in cve_records if c.severity in ['CRITICAL'])
        high = sum(1 for c in cve_records if c.severity in ['HIGH'])
        medium = sum(1 for c in cve_records if c.severity in ['MEDIUM'])
        low = sum(1 for c in cve_records if c.severity in ['LOW'])

        # Count RCE and network-exploitable CVEs
        rce_count = sum(1 for c in cve_records if c.is_rce)
        network_exploitable = sum(1 for c in cve_records if c.attack_vector == 'NETWORK')

        service_vuln = ServiceVulnerability(
            service_name=service_name,
            version=version or "unknown",
            cves=cve_records,
            total_cves=len(cve_records),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            rce_count=rce_count,
            network_exploitable_count=network_exploitable
        )

        if cve_records:
            print(f"[+] Found {len(cve_records)} CVEs (Critical: {critical}, High: {high}, Medium: {medium}, Low: {low})")
            if rce_count > 0:
                print(f"[!] WARNING: {rce_count} RCE (Remote Code Execution) vulnerabilities found!")
            if network_exploitable > 0:
                print(f"[!] {network_exploitable} network-exploitable vulnerabilities")
        else:
            print(f"[-] No CVEs found")

        return service_vuln

    def lookup_service_with_version(self, service_name: str, version: str) -> ServiceVulnerability:
        """
        Lookup CVEs for a specific service AND version combination
        More targeted than just service name search

        Args:
            service_name: Name of the service/technology
            version: Version string (e.g., "8.2p1", "1.18.0")

        Returns:
            ServiceVulnerability object with CVE records
        """
        # Normalize service name
        normalized_name = self.service_mappings.get(service_name, service_name.lower())

        # Build version-specific search query
        search_query = f"{normalized_name} {version}"

        print(f"[*] Looking up CVEs for: {service_name} {version}")

        # Query NVD with version-specific search
        response = self._make_nvd_request(search_query, results_per_page=50)

        cve_records = []
        if response:
            cve_records = self._parse_nvd_response(response)

        # Filter CVEs that actually match the version (heuristic)
        # Keep CVEs that mention the version in description or CPE matches
        version_numbers = re.findall(r'\d+\.\d+(?:\.\d+)?', version)
        if version_numbers:
            version_num = version_numbers[0]
            filtered_cves = []
            for cve in cve_records:
                # Check if version appears in description or CPE matches
                if (version_num in cve.description or
                    any(version_num in cpe for cpe in cve.cpe_matches) or
                    version in cve.description):
                    filtered_cves.append(cve)
            cve_records = filtered_cves

        # Count by severity
        critical = sum(1 for c in cve_records if c.severity in ['CRITICAL'])
        high = sum(1 for c in cve_records if c.severity in ['HIGH'])
        medium = sum(1 for c in cve_records if c.severity in ['MEDIUM'])
        low = sum(1 for c in cve_records if c.severity in ['LOW'])

        # Count RCE and network-exploitable CVEs
        rce_count = sum(1 for c in cve_records if c.is_rce)
        network_exploitable = sum(1 for c in cve_records if c.attack_vector == 'NETWORK')

        service_vuln = ServiceVulnerability(
            service_name=service_name,
            version=version,
            cves=cve_records,
            total_cves=len(cve_records),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            rce_count=rce_count,
            network_exploitable_count=network_exploitable
        )

        if cve_records:
            print(f"[+] Found {len(cve_records)} CVEs for {service_name} {version}")
            print(f"    Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")
            if rce_count > 0:
                print(f"[!] WARNING: {rce_count} RCE vulnerabilities found!")
            if network_exploitable > 0:
                print(f"[!] {network_exploitable} network-exploitable")
        else:
            print(f"[-] No CVEs found for this version")

        return service_vuln

    def get_rce_only(self, service_vuln: ServiceVulnerability) -> List[CVERecord]:
        """
        Extract only RCE vulnerabilities from a ServiceVulnerability

        Args:
            service_vuln: ServiceVulnerability object

        Returns:
            List of CVERecord objects that are RCE vulnerabilities
        """
        return [cve for cve in service_vuln.cves if cve.is_rce]


class CVEAnalyzer:
    """Analyzes HDAIS JSON output for CVE vulnerabilities"""

    def __init__(self, json_file: str, api_key: Optional[str] = None, verbose: bool = False):
        self.json_file = json_file
        self.verbose = verbose
        self.cve_lookup = CVELookup(api_key=api_key)
        self.assets_data = None
        self.service_vulnerabilities: Dict[str, ServiceVulnerability] = {}
        self.asset_vulnerabilities: Dict[str, List[ServiceVulnerability]] = {}

    def load_json(self) -> bool:
        """Load HDAIS JSON output"""
        try:
            with open(self.json_file, 'r') as f:
                self.assets_data = json.load(f)

            print(f"[+] Loaded JSON file: {self.json_file}")
            return True
        except Exception as e:
            print(f"[!] Error loading file: {e}")
            return False

    def extract_unique_services(self) -> Dict[str, int]:
        """Extract unique services/technologies from all assets"""
        service_counts = defaultdict(int)

        if not self.assets_data or 'assets' not in self.assets_data:
            return {}

        for asset in self.assets_data['assets']:
            technologies = asset.get('technologies', [])
            for tech in technologies:
                service_counts[tech] += 1

        return dict(service_counts)

    def analyze_all(self, limit: Optional[int] = None):
        """
        Analyze all services for CVE vulnerabilities

        Args:
            limit: Optional limit on number of services to check (for testing/rate limiting)
        """
        if not self.assets_data:
            print("[!] No data loaded. Call load_json() first.")
            return

        # Extract unique services
        services = self.extract_unique_services()

        if not services:
            print("[!] No services/technologies found in JSON")
            return

        print(f"\n[*] Found {len(services)} unique services/technologies")
        print(f"[*] Starting CVE lookup...\n")

        # Limit if specified
        services_to_check = list(services.items())
        if limit:
            services_to_check = services_to_check[:limit]
            print(f"[*] Limiting to first {limit} services\n")

        # Lookup CVEs for each service
        for i, (service_name, count) in enumerate(services_to_check, 1):
            print(f"\n[{i}/{len(services_to_check)}] Service: {service_name} (found in {count} assets)")

            service_vuln = self.cve_lookup.lookup_service(service_name)
            self.service_vulnerabilities[service_name] = service_vuln

        # Map vulnerabilities back to assets
        self._map_vulnerabilities_to_assets()

        print(f"\n[+] CVE analysis complete!")

    def _map_vulnerabilities_to_assets(self):
        """Map service vulnerabilities back to individual assets"""
        for asset in self.assets_data.get('assets', []):
            hostname = asset.get('hostname', '')
            technologies = asset.get('technologies', [])

            asset_vulns = []
            for tech in technologies:
                if tech in self.service_vulnerabilities:
                    service_vuln = self.service_vulnerabilities[tech]
                    if service_vuln.total_cves > 0:
                        asset_vulns.append(service_vuln)

            if asset_vulns:
                self.asset_vulnerabilities[hostname] = asset_vulns

    def _sort_cves_by_severity(self, cves: List[CVERecord]) -> List[CVERecord]:
        """
        Sort CVEs by severity (Critical -> High -> Medium -> Low -> Unknown)
        Within same severity, sort by CVSS score descending
        """
        severity_order = {
            'CRITICAL': 0,
            'HIGH': 1,
            'MEDIUM': 2,
            'LOW': 3,
            'UNKNOWN': 4
        }

        def sort_key(cve: CVERecord):
            severity = cve.severity.upper()
            return (severity_order.get(severity, 4), -cve.cvss_score)

        return sorted(cves, key=sort_key)

    def generate_report(self, output_file: str = None):
        """Generate CVE analysis report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if output_file is None:
            output_file = f"cve_analysis_{timestamp}.json"

        # Calculate statistics
        total_services_checked = len(self.service_vulnerabilities)
        services_with_cves = sum(1 for s in self.service_vulnerabilities.values() if s.total_cves > 0)
        total_cves = sum(s.total_cves for s in self.service_vulnerabilities.values())
        total_critical = sum(s.critical_count for s in self.service_vulnerabilities.values())
        total_high = sum(s.high_count for s in self.service_vulnerabilities.values())

        report = {
            'metadata': {
                'analysis_timestamp': datetime.now().isoformat(),
                'source_file': self.json_file,
                'analyzer_version': '1.0.0',
            },
            'statistics': {
                'total_services_checked': total_services_checked,
                'services_with_vulnerabilities': services_with_cves,
                'total_cves_found': total_cves,
                'total_critical': total_critical,
                'total_high': total_high,
                'assets_with_vulnerabilities': len(self.asset_vulnerabilities)
            },
            'service_vulnerabilities': {
                name: {
                    'service_name': vuln.service_name,
                    'version': vuln.version,
                    'total_cves': vuln.total_cves,
                    'critical_count': vuln.critical_count,
                    'high_count': vuln.high_count,
                    'medium_count': vuln.medium_count,
                    'low_count': vuln.low_count,
                    'cves': [asdict(cve) for cve in self._sort_cves_by_severity(vuln.cves)[:10]]  # Top 10 CVEs per service, sorted by severity
                }
                for name, vuln in self.service_vulnerabilities.items()
                if vuln.total_cves > 0
            },
            'asset_vulnerabilities': {
                hostname: [
                    {
                        'service': v.service_name,
                        'cve_count': v.total_cves,
                        'critical': v.critical_count,
                        'high': v.high_count
                    }
                    for v in vulns
                ]
                for hostname, vulns in self.asset_vulnerabilities.items()
            },
            'high_priority_services': self._get_high_priority_services()
        }

        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n[+] CVE report saved to: {output_file}")

        # Generate markdown summary
        summary_file = output_file.replace('.json', '_summary.md')
        self._generate_markdown_summary(summary_file, report)
        print(f"[+] Summary report saved to: {summary_file}")

        return report

    def _get_high_priority_services(self) -> List[Dict]:
        """Get services prioritized by severity"""
        priority_list = []

        for name, vuln in self.service_vulnerabilities.items():
            if vuln.total_cves > 0:
                priority_score = (vuln.critical_count * 10 +
                                vuln.high_count * 5 +
                                vuln.medium_count * 2 +
                                vuln.low_count * 1)

                priority_list.append({
                    'service_name': name,
                    'priority_score': priority_score,
                    'total_cves': vuln.total_cves,
                    'critical': vuln.critical_count,
                    'high': vuln.high_count,
                    'medium': vuln.medium_count,
                    'low': vuln.low_count
                })

        return sorted(priority_list, key=lambda x: x['priority_score'], reverse=True)

    def _generate_markdown_summary(self, output_file: str, report: Dict):
        """Generate human-readable markdown summary"""
        stats = report['statistics']

        md = f"""# CVE Vulnerability Analysis Report

**Generated:** {report['metadata']['analysis_timestamp']}
**Source:** {report['metadata']['source_file']}

## Executive Summary

This report identifies known CVE vulnerabilities in services and technologies detected across university AI infrastructure.

### Key Findings

- **Services Analyzed:** {stats['total_services_checked']}
- **Services with Vulnerabilities:** {stats['services_with_vulnerabilities']}
- **Total CVEs Found:** {stats['total_cves_found']}
  - Critical: {stats['total_critical']}
  - High: {stats['total_high']}
- **Assets Affected:** {stats['assets_with_vulnerabilities']}

---

## High-Priority Services (by Risk Score)

"""

        high_priority = report.get('high_priority_services', [])
        if high_priority:
            md += "| Service | Priority Score | Total CVEs | Critical | High | Medium | Low |\n"
            md += "|---------|----------------|------------|----------|------|--------|-----|\n"

            for service in high_priority[:15]:  # Top 15
                md += f"| {service['service_name']} | {service['priority_score']} | {service['total_cves']} | {service['critical']} | {service['high']} | {service['medium']} | {service['low']} |\n"
        else:
            md += "No high-priority services found.\n"

        md += "\n---\n\n## Detailed Service Vulnerabilities\n\n"

        for service_name, vuln_data in sorted(
            report['service_vulnerabilities'].items(),
            key=lambda x: (x[1]['critical_count'], x[1]['high_count']),
            reverse=True
        ):
            if vuln_data['total_cves'] > 0:
                md += f"### {service_name}\n\n"
                md += f"- **Total CVEs:** {vuln_data['total_cves']}\n"
                md += f"- **Critical:** {vuln_data['critical_count']}\n"
                md += f"- **High:** {vuln_data['high_count']}\n"
                md += f"- **Medium:** {vuln_data['medium_count']}\n"
                md += f"- **Low:** {vuln_data['low_count']}\n\n"

                # Show top 5 CVEs for this service
                if vuln_data['cves']:
                    md += "**Top CVEs:**\n\n"
                    for cve in vuln_data['cves'][:5]:
                        md += f"#### {cve['cve_id']} ({cve['severity']}, CVSS: {cve['cvss_score']})\n\n"
                        md += f"{cve['description'][:300]}...\n\n"
                        if cve['references']:
                            md += f"**References:** {', '.join(cve['references'][:2])}\n\n"

                md += "---\n\n"

        # Assets with vulnerabilities
        md += "## Assets with Vulnerabilities\n\n"

        asset_vulns = report.get('asset_vulnerabilities', {})
        if asset_vulns:
            md += f"Total assets with vulnerabilities: {len(asset_vulns)}\n\n"

            # Show top 10 most vulnerable assets
            sorted_assets = sorted(
                asset_vulns.items(),
                key=lambda x: sum(v['cve_count'] for v in x[1]),
                reverse=True
            )

            md += "### Top 10 Most Vulnerable Assets\n\n"
            for hostname, vulns in sorted_assets[:10]:
                total_cves = sum(v['cve_count'] for v in vulns)
                total_critical = sum(v['critical'] for v in vulns)
                total_high = sum(v['high'] for v in vulns)

                md += f"#### {hostname}\n\n"
                md += f"- **Total CVEs:** {total_cves}\n"
                md += f"- **Critical:** {total_critical}\n"
                md += f"- **High:** {total_high}\n"
                md += f"- **Vulnerable Services:** {', '.join([v['service'] for v in vulns])}\n\n"

        # Recommendations
        md += "\n---\n\n## Recommendations\n\n"
        md += """
1. **Immediate Actions:**
   - Patch or upgrade services with CRITICAL vulnerabilities
   - Review and restrict access to services with HIGH severity CVEs
   - Implement monitoring for exploitation attempts

2. **Short-term (1-4 weeks):**
   - Create patching schedule for MEDIUM severity vulnerabilities
   - Conduct deeper security assessment of top 10 vulnerable assets
   - Implement WAF or IPS rules for known exploits

3. **Long-term:**
   - Establish automated vulnerability scanning pipeline
   - Implement continuous monitoring for new CVEs
   - Create security baseline for university AI infrastructure

4. **Process Improvements:**
   - Integrate CVE checking into deployment pipeline
   - Establish vulnerability disclosure and response process
   - Train IT staff on security patching best practices

---

*This report is part of HDAIS (Higher Education Digital Asset Intelligence System) audit toolkit*
"""

        with open(output_file, 'w') as f:
            f.write(md)

    def print_summary(self):
        """Print brief summary to console"""
        print("\n" + "="*70)
        print("CVE VULNERABILITY ANALYSIS SUMMARY")
        print("="*70)

        total_services = len(self.service_vulnerabilities)
        services_with_vulns = sum(1 for s in self.service_vulnerabilities.values() if s.total_cves > 0)

        print(f"\nServices Analyzed: {total_services}")
        print(f"Services with Vulnerabilities: {services_with_vulns}")

        if services_with_vulns > 0:
            print("\nTop 5 Most Vulnerable Services:")

            sorted_services = sorted(
                [(name, vuln) for name, vuln in self.service_vulnerabilities.items() if vuln.total_cves > 0],
                key=lambda x: (x[1].critical_count, x[1].high_count, x[1].total_cves),
                reverse=True
            )

            for i, (name, vuln) in enumerate(sorted_services[:5], 1):
                print(f"\n{i}. {name}")
                print(f"   Total CVEs: {vuln.total_cves}")
                print(f"   Critical: {vuln.critical_count}, High: {vuln.high_count}, Medium: {vuln.medium_count}")

        print(f"\nAssets Affected: {len(self.asset_vulnerabilities)}")
        print("\n" + "="*70 + "\n")


def main():
    """Command-line interface for CVE analyzer"""
    parser = argparse.ArgumentParser(
        description='CVE Vulnerability Analyzer - Check services against CVE databases',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  %(prog)s full_assets_20240101_120000.json

  # With NVD API key (higher rate limits)
  %(prog)s full_assets.json --api-key YOUR_API_KEY

  # Limit to first 10 services (for testing)
  %(prog)s full_assets.json --limit 10

  # Verbose output
  %(prog)s full_assets.json --verbose
        """
    )

    parser.add_argument('json_file', help='JSON file from HDAIS')
    parser.add_argument('-k', '--api-key', help='NVD API key (optional, increases rate limit)')
    parser.add_argument('-o', '--output', help='Output file for CVE report')
    parser.add_argument('-l', '--limit', type=int, help='Limit number of services to check')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--no-summary', action='store_true', help='Skip console summary')

    args = parser.parse_args()

    # Create analyzer
    analyzer = CVEAnalyzer(args.json_file, api_key=args.api_key, verbose=args.verbose)

    # Load and analyze
    if not analyzer.load_json():
        return 1

    analyzer.analyze_all(limit=args.limit)

    # Generate report
    analyzer.generate_report(args.output)

    # Print summary
    if not args.no_summary:
        analyzer.print_summary()

    return 0


if __name__ == "__main__":
    exit(main())
