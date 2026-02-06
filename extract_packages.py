#!/usr/bin/env python3
"""
Script to extract all open source packages from Jupyter notebooks and Python files.
Can analyze local files or clone a GitHub repository and extract packages from all files.
Also scans packages for vulnerabilities using OSV.dev API.

Usage:
    python extract_packages.py                                # Analyze local notebook
    python extract_packages.py --github https://github.com/user/repo
    python extract_packages.py --file path/to/file.ipynb
    python extract_packages.py --scan-vulnerabilities          # Extract + scan
    python extract_packages.py --from-extracted                # Scan extracted_packages.txt
"""

import json
import re
import shutil
import tempfile
import argparse
import subprocess
import requests
import mysql.connector
import os
from openai import OpenAI
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from typing import Set, List, Dict, Tuple
try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    # Fallback for Python < 3.8
    try:
        from importlib_metadata import version, PackageNotFoundError
    except ImportError:
        print("⚠️  Warning: importlib.metadata not available, version checking may be limited")
        version = None
        PackageNotFoundError = Exception


# OpenAI client for risk summary generation
if os.environ.get("OPENAI_API_KEY"):
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
else:
    client = None
    print("⚠️  Warning: OPENAI_API_KEY not found. Risk summary generation will be skipped.")

# System prompt for risk summary generation
SYSTEM = """You are OSS DevAssist.
Write a risk summary based ONLY on provided package inventory, vulnerabilities, and file context.
Hard rules:
- Output must be under MAX_CHARS characters.
- No markdown, no bullets unless needed.
- No invented CVEs, versions, or claims.
- If evidence is missing, say so briefly.
"""


def extract_imports_from_code(code: str) -> Set[str]:
    """
    Extract package names from Python code containing import statements.
    
    Args:
        code: Python code as string
        
    Returns:
        Set of package names
    """
    packages = set()
    
    # Pattern for: import module
    import_pattern = r'^\s*import\s+([a-zA-Z0-9_]+)'
    
    # Pattern for: import module as alias
    import_as_pattern = r'^\s*import\s+([a-zA-Z0-9_\.]+)\s+as\s+'
    
    # Pattern for: from module import something
    from_pattern = r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import\s+'
    
    for line in code.split('\n'):
        # Skip comments and empty lines
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Match: import X
        match = re.match(import_pattern, line)
        if match:
            pkg = match.group(1).split('.')[0]  # Get top-level module
            packages.add(pkg)
            continue
        
        # Match: import X as Y
        match = re.match(import_as_pattern, line)
        if match:
            pkg = match.group(1).split('.')[0]  # Get top-level module
            packages.add(pkg)
            continue
        
        # Match: from X import Y
        match = re.match(from_pattern, line)
        if match:
            pkg = match.group(1).split('.')[0]  # Get top-level module
            packages.add(pkg)
            continue
    
    return packages


def extract_packages_from_notebook(notebook_path: str) -> Set[str]:
    """
    Extract all package names from a Jupyter notebook file.
    
    Args:
        notebook_path: Path to the .ipynb file
        
    Returns:
        Set of package names
    """
    with open(notebook_path, 'r', encoding='utf-8') as f:
        notebook = json.load(f)
    
    all_packages = set()
    
    # Iterate through all cells
    for cell in notebook.get('cells', []):
        # Only process code cells
        if cell.get('cell_type') == 'code':
            # Get source code (can be list or string)
            source = cell.get('source', [])
            if isinstance(source, list):
                code = ''.join(source)
            else:
                code = source
            
            # Extract packages from this cell
            packages = extract_imports_from_code(code)
            all_packages.update(packages)
    
    return all_packages


def extract_packages_from_directory(directory: str) -> Set[str]:
    """
    Extract packages from all Python and Jupyter notebook files in a directory.
    
    Args:
        directory: Path to directory to scan
        
    Returns:
        Set of all package names found
    """
    all_packages = set()
    directory = Path(directory)
    
    if not directory.exists():
        print(f"❌ Directory not found: {directory}")
        return all_packages
    
    # Find all Python files
    python_files = list(directory.glob("**/*.py"))
    notebook_files = list(directory.glob("**/*.ipynb"))
    
    print(f"📂 Found {len(python_files)} Python files and {len(notebook_files)} Jupyter notebooks\n")
    
    # Extract from Python files
    for py_file in python_files:
        try:
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
                packages = extract_imports_from_code(code)
                all_packages.update(packages)
        except Exception as e:
            print(f"⚠️  Error reading {py_file}: {e}")
    
    # Extract from Jupyter notebooks
    for nb_file in notebook_files:
        try:
            packages = extract_packages_from_notebook(str(nb_file))
            all_packages.update(packages)
        except Exception as e:
            print(f"⚠️  Error reading {nb_file}: {e}")
    
    return all_packages


def clone_github_repo(github_url: str, keep_local: bool = False) -> str:
    """
    Clone a GitHub repository to a directory.
    
    Args:
        github_url: GitHub repository URL
        keep_local: If True, save to local 'github_repos' directory instead of temp
        
    Returns:
        Path to cloned repository
    """
    if keep_local:
        # Create 'github_repos' directory if it doesn't exist
        repos_dir = Path(__file__).parent / "github_repos"
        repos_dir.mkdir(exist_ok=True)
        
        # Extract repo name from URL
        repo_name = github_url.rstrip('/').split('/')[-1].replace('.git', '')
        clone_path = repos_dir / repo_name
        
        # Remove existing directory if it exists
        if clone_path.exists():
            shutil.rmtree(clone_path)
    else:
        # Create temporary directory
        clone_path = tempfile.mkdtemp(prefix="github_repo_")
    
    try:
        print(f"📥 Cloning repository from {github_url}...")
        subprocess.run(
            ["git", "clone", "--depth", "1", github_url, str(clone_path)],
            check=True,
            capture_output=True,
            timeout=60
        )
        print(f"✅ Repository cloned to: {clone_path}\n")
        return str(clone_path)
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to clone repository: {e.stderr.decode()}")
        return None
    except subprocess.TimeoutExpired:
        print(f"❌ Cloning timed out")
        return None


def filter_stdlib_packages(packages: Set[str]) -> tuple:
    """
    Separate standard library packages from third-party packages.
    
    Args:
        packages: Set of package names
        
    Returns:
        Tuple of (third_party_packages, stdlib_packages)
    """
    # Common Python standard library modules
    stdlib = {
        'sys', 'os', 'json', 're', 'time', 'datetime', 'collections', 
        'itertools', 'functools', 'operator', 'math', 'random', 'statistics',
        'pathlib', 'glob', 'fnmatch', 'pickle', 'csv', 'configparser',
        'hashlib', 'hmac', 'secrets', 'string', 'io', 'abc', 'warnings',
        'contextlib', 'threading', 'multiprocessing', 'subprocess', 'socket',
        'ssl', 'urllib', 'http', 'ftplib', 'poplib', 'imaplib', 'smtplib',
        'uuid', 'socketserver', 'xmlrpc', 'ipaddress', 'argparse', 'getopt',
        'logging', 'getpass', 'curses', 'platform', 'errno', 'ctypes',
        'types', 'copy', 'pprint', 'enum', 'graphlib', 'heapq', 'bisect',
        'array', 'struct', 'codecs', 'textwrap', 'unicodedata', 'stringprep',
        'readline', 'rlcompleter', 'zipfile', 'tarfile', 'gzip', 'bz2',
        'lzma', 'dbm', 'sqlite3', 'zlib', 'gzip', 'bz2', 'lzma', 'zlib',
        'IPython', 'pytest', 'unittest', 'doctest', 'pdb', 'cProfile',
        'tracemalloc', 'gc', 'inspect', 'site', '__future__'
    }
    
    third_party = set()
    stdlib_found = set()
    
    for pkg in packages:
        if pkg in stdlib:
            stdlib_found.add(pkg)
        else:
            third_party.add(pkg)
    
    return third_party, stdlib_found


def get_installed_packages_versions(packages: Set[str]) -> Dict[str, Tuple[str, bool]]:
    """
    Check which packages are installed and their versions.
    Uses multiple methods to find package versions (importlib.metadata and pip list).
    
    Args:
        packages: Set of package names to check
        
    Returns:
        Dictionary mapping package name to (version, is_installed) tuple
    """
    # Common mapping of import names to pip package names
    import_to_pip_map = {
        'sklearn': 'scikit-learn',
        'cv2': 'opencv-python',
        'PIL': 'Pillow',
        'yaml': 'PyYAML',
        'sqlalchemy': 'SQLAlchemy',
        'OpenSSL': 'pyOpenSSL',
        'dotenv': 'python-dotenv',
        'pkg_resources': 'setuptools',
        'MySQLdb': 'mysqlclient',
        'mysql': 'mysql-connector-python',
    }
    
    versions = {}
    pip_installed = None  # Cache for pip list results
    
    for pkg in packages:
        found = False
        
        # Try 1: Direct lookup with importlib.metadata
        if version:
            try:
                pkg_version = version(pkg)
                versions[pkg] = (pkg_version, True)
                found = True
                continue
            except:
                pass
            
            # Try 2: Try replacing underscores with hyphens
            try:
                pkg_alt = pkg.replace('_', '-')
                pkg_version = version(pkg_alt)
                versions[pkg] = (pkg_version, True)
                found = True
                continue
            except:
                pass
            
            # Try 3: Use known import-to-pip name mapping
            if pkg in import_to_pip_map:
                try:
                    pkg_version = version(import_to_pip_map[pkg])
                    versions[pkg] = (pkg_version, True)
                    found = True
                    continue
                except:
                    pass
        
        # Try 4: Use pip list as fallback (cached)
        if pip_installed is None:
            try:
                result = subprocess.run(
                    ['pip', 'list', '--format=json'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    pip_data = json.loads(result.stdout)
                    pip_installed = {item['name'].lower(): item['version'] for item in pip_data}
                else:
                    pip_installed = {}
            except Exception:
                pip_installed = {}
        
        if pip_installed:
            # Try direct lookup in pip list
            pkg_lower = pkg.lower()
            if pkg_lower in pip_installed:
                versions[pkg] = (pip_installed[pkg_lower], True)
                found = True
                continue
            
            # Try with hyphens
            pkg_hyphen = pkg.lower().replace('_', '-')
            if pkg_hyphen in pip_installed:
                versions[pkg] = (pip_installed[pkg_hyphen], True)
                found = True
                continue
            
            # Try mapped name
            if pkg in import_to_pip_map:
                mapped_lower = import_to_pip_map[pkg].lower()
                if mapped_lower in pip_installed:
                    versions[pkg] = (pip_installed[mapped_lower], True)
                    found = True
                    continue
        
        # If still not found, mark as not installed
        if not found:
            versions[pkg] = (None, False)
    
    return versions


def scan_vulnerabilities_osv(package_name: str, package_version: str = None) -> List[Dict]:
    """
    Scan a package for vulnerabilities using OSV.dev API.
    
    Args:
        package_name: Name of the package to scan
        package_version: Optional specific version to check
        
    Returns:
        List of vulnerability dictionaries
    """
    try:
        url = "https://api.osv.dev/v1/query"
        
        # Prepare query
        query = {
            "package": {"name": package_name, "ecosystem": "PyPI"},
        }
        
        if package_version:
            query["version"] = package_version
        
        response = requests.post(url, json=query, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        vulns = data.get("vulns", [])
        return vulns
    
    except requests.exceptions.RequestException as e:
        print(f"⚠️  Error querying OSV.dev for {package_name}: {e}")
        return []
    except Exception as e:
        print(f"⚠️  Unexpected error querying OSV.dev for {package_name}: {e}")
        return []


def scan_all_packages_vulnerabilities(packages_with_versions: Dict[str, Tuple[str, bool]]) -> Dict[str, List[Dict]]:
    """
    Scan all packages for vulnerabilities.
    
    Args:
        packages_with_versions: Dict of package_name -> (version, is_installed)
        
    Returns:
        Dictionary mapping package names to list of vulnerabilities
    """
    vulnerabilities = {}
    installed_packages = {
        pkg: ver for pkg, (ver, is_installed) in packages_with_versions.items() if is_installed
    }
    
    if not installed_packages:
        print("⚠️  No installed packages to scan for vulnerabilities.")
        return vulnerabilities
    
    total = len(installed_packages)
    print(f"🔍 Scanning {total} packages for vulnerabilities on OSV.dev...\n")
    
    for idx, (pkg, version_str) in enumerate(sorted(installed_packages.items()), 1):
        print(f"  [{idx}/{total}] Scanning {pkg} ({version_str})... ", end="", flush=True)
        
        vulns = scan_vulnerabilities_osv(pkg, version_str)
        
        if vulns:
            vulnerabilities[pkg] = vulns
            print(f"⚠️  Found {len(vulns)} vulnerability/ies")
        else:
            print("✅ No vulnerabilities found")
    
    print()
    return vulnerabilities


def display_vulnerabilities(vulnerabilities: Dict[str, List[Dict]]):
    """
    Display vulnerability scan results.
    
    Args:
        vulnerabilities: Dictionary mapping package names to vulnerabilities
    """
    if not vulnerabilities:
        print("=" * 70)
        print("VULNERABILITY SCAN RESULTS")
        print("=" * 70)
        print("\n✅ No vulnerabilities found in scanned packages!\n")
        return
    
    print("=" * 70)
    print("VULNERABILITY SCAN RESULTS - OSV.dev")
    print("=" * 70)
    print()
    
    total_vulns = sum(len(v) for v in vulnerabilities.values())
    print(f"⚠️  Found {total_vulns} vulnerabilities in {len(vulnerabilities)} packages:\n")
    
    for pkg, vulns in sorted(vulnerabilities.items()):
        print(f"\n📦 {pkg}")
        print("  " + "-" * 66)
        
        for idx, vuln in enumerate(vulns, 1):
            vuln_id = vuln.get("id", "N/A")
            summary = vuln.get("summary", "No summary available")
            severity = vuln.get("severity", "UNKNOWN")
            affected = vuln.get("affected", [])
            
            print(f"  [{idx}] ID: {vuln_id}")
            print(f"      Severity: {severity}")
            print(f"      Summary: {summary}")
            
            if affected:
                print(f"      Affected versions: {affected[0].get('versions', 'N/A')}")
            
            print()
    
    print("=" * 70)
    print(f"Total vulnerabilities: {total_vulns}")
    print("=" * 70)
    print()


def save_vulnerability_report(vulnerabilities: Dict[str, List[Dict]], output_file: Path = None):
    """
    Save vulnerability report to file.
    
    Args:
        vulnerabilities: Dictionary of vulnerabilities
        output_file: Path to save report (default: vulnerability_report.json)
    """
    if output_file is None:
        output_file = Path(__file__).parent / "vulnerability_report.json"
    
    report = {
        "total_packages_scanned": len(vulnerabilities),
        "total_vulnerabilities": sum(len(v) for v in vulnerabilities.values()),
        "vulnerabilities": vulnerabilities
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"💾 Vulnerability report saved to: {output_file}")
    return report


def get_vulnerability_from_osv(vuln_id: str) -> Dict:
    """
    Query OSV.dev API for a vulnerability by ID to get complete field data.
    
    Args:
        vuln_id: Vulnerability ID (e.g., GHSA-xxxx, CVE-xxxx, PYSEC-xxxx)
    
    Returns:
        Complete vulnerability data from OSV.dev API
    """
    try:
        url = "https://api.osv.dev/v1/query"
        payload = {"query": vuln_id}
        response = requests.post(url, json=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('vulns'):
                return data['vulns'][0]  # Return first match
    except Exception as e:
        print(f"⚠️  Warning: Could not fetch vulnerability {vuln_id} from OSV.dev: {e}")
    
    return {}


def enrich_vulnerability_fields(vuln: Dict) -> Dict:
    """
    Enrich a vulnerability object by adding missing fields found in dependencies.json.
    
    Missing fields to add:
    - schema_version (top level)
    - database_specific.source (in affected[].database_specific)
    
    Args:
        vuln: Vulnerability object from vulnerability_report.json
    
    Returns:
        Enriched vulnerability object
    """
    enriched_vuln = vuln.copy()
    vuln_id = vuln.get('id')
    
    if not vuln_id:
        return enriched_vuln
    
    # Fetch complete vulnerability data from OSV.dev
    complete_vuln = get_vulnerability_from_osv(vuln_id)
    
    if not complete_vuln:
        print(f"⚠️  Could not fetch complete data for {vuln_id}")
        return enriched_vuln
    
    # Add schema_version if missing
    if 'schema_version' not in enriched_vuln and 'schema_version' in complete_vuln:
        enriched_vuln['schema_version'] = complete_vuln['schema_version']
        print(f"✅ Added schema_version to {vuln_id}")
    
    # Enhance affected array with database_specific.source if missing
    if 'affected' in enriched_vuln and isinstance(enriched_vuln['affected'], list):
        for i, affected in enumerate(enriched_vuln['affected']):
            if isinstance(affected, dict):
                # Check if database_specific.source is missing
                if ('database_specific' not in affected or 
                    'source' not in affected.get('database_specific', {})):
                    
                    # Find corresponding affected entry in complete data
                    if 'affected' in complete_vuln and isinstance(complete_vuln['affected'], list):
                        for complete_affected in complete_vuln['affected']:
                            # Match by package name
                            vuln_pkg_name = affected.get('package', {}).get('name')
                            complete_pkg_name = complete_affected.get('package', {}).get('name')
                            
                            if vuln_pkg_name == complete_pkg_name:
                                # Add missing database_specific.source
                                if 'database_specific' in complete_affected:
                                    if 'database_specific' not in affected:
                                        affected['database_specific'] = {}
                                    if 'source' not in affected['database_specific']:
                                        affected['database_specific']['source'] = complete_affected['database_specific']['source']
                                        print(f"✅ Added database_specific.source to {vuln_id} affected entry {i}")
                                break
    
    return enriched_vuln


def enrich_vulnerability_report(vuln_report: Dict) -> Dict:
    """
    Enrich the entire vulnerability report by adding missing fields.
    
    Args:
        vuln_report: Original vulnerability report from vulnerability_report.json
    
    Returns:
        Enriched vulnerability report with additional fields
    """
    enriched_report = vuln_report.copy()
    enriched_report['vulnerabilities'] = {}
    
    print("🔄 Enriching vulnerability report with missing fields...")
    
    # Process each package's vulnerabilities
    for pkg_name, vulns in vuln_report.get('vulnerabilities', {}).items():
        enriched_vulns = []
        
        for vuln in vulns:
            enriched_vuln = enrich_vulnerability_fields(vuln)
            enriched_vulns.append(enriched_vuln)
        
        enriched_report['vulnerabilities'][pkg_name] = enriched_vulns
    
    # Add enrichment metadata
    enriched_report['enrichment_metadata'] = {
        'method': 'Field enrichment from OSV.dev API',
        'reference_comparison': 'dependencies.json structure',
        'fields_added': [
            'schema_version (top level)',
            'database_specific.source (in affected array)'
        ],
        'source': 'OSV.dev API queries by vulnerability ID',
        'note': 'Only missing fields were added - no data from dependencies.json was imported'
    }
    
    return enriched_report


def generate_enrichment_summary(original_report: Dict, enriched_report: Dict) -> str:
    """Generate a summary of what was enriched."""
    summary = []
    summary.append("=" * 80)
    summary.append("VULNERABILITY REPORT ENRICHMENT SUMMARY")
    summary.append("=" * 80)
    summary.append("")
    
    # Count fields added
    schema_versions_added = 0
    sources_added = 0
    
    for pkg_name, vulns in enriched_report.get('vulnerabilities', {}).items():
        for vuln in vulns:
            if 'schema_version' in vuln:
                schema_versions_added += 1
            
            if 'affected' in vuln:
                for affected in vuln['affected']:
                    if affected.get('database_specific', {}).get('source'):
                        sources_added += 1
    
    summary.append("📊 Enrichment Results:")
    summary.append(f"  - Total vulnerabilities processed: {original_report.get('total_vulnerabilities', 0)}")
    summary.append(f"  - schema_version fields added: {schema_versions_added}")
    summary.append(f"  - database_specific.source fields added: {sources_added}")
    summary.append("")
    
    summary.append("🔍 Fields Added:")
    summary.append("  - schema_version: OSV schema version for the vulnerability")
    summary.append("  - database_specific.source: Source URL of the advisory database entry")
    summary.append("")
    
    summary.append("📋 Method:")
    summary.append("  - Compared vulnerability_report.json structure with dependencies.json")
    summary.append("  - Identified missing fields: schema_version, database_specific.source")
    summary.append("  - Fetched missing fields from OSV.dev API using vulnerability IDs")
    summary.append("  - No data was imported from dependencies.json")
    summary.append("")
    
    summary.append("=" * 80)
    
    return "\n".join(summary)


def load_packages_from_extracted_file(file_path: Path = None) -> Dict[str, str]:
    """
    Load packages from extracted_packages.txt file.
    
    Args:
        file_path: Path to extracted_packages.txt (default: search in current dir)
        
    Returns:
        Dictionary mapping package names to versions
    """
    if file_path is None:
        file_path = Path(__file__).parent / "extracted_packages.txt"
    
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        print("   Run the script first to generate extracted_packages.txt")
        return {}
    
    packages = {}
    in_packages_section = False
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            
            if line.startswith("THIRD-PARTY PACKAGES"):
                in_packages_section = True
                continue
            
            if line.startswith("SOURCE:") or line.startswith("==="):
                if in_packages_section:
                    break
            
            if in_packages_section and line and not line.startswith("==="):
                # Parse package line: "package==version" or "package  (NOT INSTALLED)"
                if "==" in line:
                    pkg_name, pkg_version = line.split("==", 1)
                    packages[pkg_name.strip()] = pkg_version.strip()
                elif "NOT INSTALLED" in line:
                    pkg_name = line.split("(NOT INSTALLED)")[0].strip()
                    packages[pkg_name] = "NOT INSTALLED"
                else:
                    packages[line] = "UNKNOWN"
    
    return packages


def display_results(all_packages: Set[str], source: str, repo_path: str = None, check_versions: bool = True):
    """
    Display extracted packages in organized format.
    
    Args:
        all_packages: Set of all package names
        source: Description of where packages came from
        repo_path: Optional path to repository (for saving reference)
        check_versions: Whether to check installed package versions
    """
    # Filter into third-party and stdlib
    third_party, stdlib = filter_stdlib_packages(all_packages)
    
    # Get version information if requested
    installed_versions = {}
    if check_versions and third_party:
        print("🔍 Checking installed package versions...\n")
        installed_versions = get_installed_packages_versions(third_party)
    
    print("=" * 70)
    print(f"SOURCE: {source}")
    if repo_path:
        print(f"PATH: {repo_path}")
    print("=" * 70)
    print()
    
    # Display results
    print("=" * 70)
    print("THIRD-PARTY PACKAGES (Open Source Dependencies)")
    print("=" * 70)
    
    if third_party:
        installed_count = 0
        missing_count = 0
        
        for pkg in sorted(third_party):
            if check_versions and pkg in installed_versions:
                pkg_version, is_installed = installed_versions[pkg]
                if is_installed:
                    print(f"  ✅ {pkg:<20} v{pkg_version}")
                    installed_count += 1
                else:
                    print(f"  ❌ {pkg:<20} NOT INSTALLED")
                    missing_count += 1
            else:
                print(f"  • {pkg}")
        
        print(f"\n📦 Total: {len(third_party)} third-party packages")
        if check_versions:
            print(f"   - Installed: {installed_count}")
            print(f"   - Missing: {missing_count}\n")
        else:
            print()
    else:
        print("  No third-party packages found.\n")
    
    print("=" * 70)
    print("PYTHON STANDARD LIBRARY MODULES")
    print("=" * 70)
    
    if stdlib:
        for pkg in sorted(stdlib):
            print(f"  • {pkg}")
        print(f"\n📚 Total: {len(stdlib)} stdlib modules\n")
    else:
        print("  No stdlib modules found.\n")
    
    print("=" * 70)
    print(f"SUMMARY")
    print("=" * 70)
    print(f"Total unique imports: {len(all_packages)}")
    print(f"  - Third-party: {len(third_party)}")
    print(f"  - Standard library: {len(stdlib)}")
    print()
    
    # Export unique packages to a file
    output_file = Path(__file__).parent / "extracted_packages.txt"
    with open(output_file, 'w') as f:
        for pkg in sorted(third_party):
            if check_versions and pkg in installed_versions:
                pkg_version, is_installed = installed_versions[pkg]
                if is_installed:
                    f.write(f"{pkg}=={pkg_version}\n")
                else:
                    f.write(f"{pkg}  (NOT INSTALLED)\n")
            else:
                f.write(f"{pkg}\n")
    
    print(f"💾 Package list saved to: {output_file}")
    return third_party, installed_versions


# ---------------------------------------------------------------
# Risk Summary Generation Functions
# ---------------------------------------------------------------

def extract_file_context(file_path: str, packages: list, max_chars: int = 4000) -> str:
    """Extract relevant context from a Python file for packages."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return ""

    pkg_names = [p.get("name","") for p in packages if isinstance(p, dict)]
    tokens = set()
    for name in pkg_names:
        if not name:
            continue
        tokens.add(name)
        tokens.add(name.replace("-", "_"))

    lines = []
    for ln in content.splitlines():
        s = ln.strip()
        if s.startswith("!pip install") or s.startswith("pip install"):
            lines.append(s)
        elif s.startswith("import ") or s.startswith("from "):
            lines.append(s)
        elif any((t + ".") in s for t in tokens):
            lines.append(s[:200])

    ctx = "\n".join(lines)
    return ctx[:max_chars]


def enforce_max_chars(text: str, max_chars: int) -> str:
    """Ensure text doesn't exceed max_chars."""
    text = " ".join(text.split())  # normalize whitespace
    if len(text) <= max_chars:
        return text
    # hard truncate with ellipsis
    return text[: max(0, max_chars - 1)] + "…"


def generate_risk_summary(package_name: str, vulnerabilities: list, file_context: str, max_chars: int = 500) -> str:
    """Generate risk summary using OpenAI API."""
    if not client:
        return f"Risk summary not available: OpenAI API key not configured for package {package_name}."
    
    try:
        # Build context similar to the notebook
        context = {
            "package": package_name,
            "vulnerabilities": vulnerabilities,
            "file_context": file_context,
            "MAX_CHARS": max_chars,
        }

        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Generate a risk summary under {max_chars} characters for package {package_name}.\nContext:\n{json.dumps(context)}"},
            ],
            max_tokens=500,
            temperature=0.3,
        )

        out = resp.choices[0].message.content or ""
        return enforce_max_chars(out, max_chars)
    except Exception as e:
        return f"Risk summary generation failed: {e}"


def generate_all_risk_summaries(repo_path: str, vulnerability_report: dict):
    """Generate risk summaries for all vulnerable packages (per vulnerability)."""
    summaries = {}

    # Get vulnerable packages
    vulnerabilities_data = vulnerability_report.get("vulnerabilities", {})

    for package_name, vuln_list in vulnerabilities_data.items():
        if not vuln_list:
            continue

        # Find files that use this package
        package_files = find_files_using_package(repo_path, package_name)
        rel_files = [os.path.relpath(p, repo_path) for p in package_files[:3]]

        if not package_files:
            base_context = (
                f"Package {package_name} found in repository but specific usage files not identified."
            )
        else:
            contexts = []
            for file_path in package_files[:3]:  # Limit to 3 files per package
                ctx = extract_file_context(file_path, [{"name": package_name}])
                if ctx:
                    contexts.append(f"FILE: {os.path.relpath(file_path, repo_path)}\n{ctx}")
            base_context = "\n\n".join(contexts) if contexts else (
                f"Package {package_name} found in repository but file context was empty."
            )

        summaries[package_name] = {
            "vulnerabilities": {},
            "files": rel_files,
            "vulnerabilities_count": len(vuln_list)
        }

        # Generate summary per vulnerability
        for vuln in vuln_list:
            vuln_id = vuln.get("id") or "UNKNOWN_ID"
            summary = generate_risk_summary(package_name, [vuln], base_context)
            summaries[package_name]["vulnerabilities"][vuln_id] = {
                "summary": summary,
                "files": rel_files
            }

    print(summaries)
    return summaries


def find_files_using_package(repo_path: str, package_name: str) -> List[str]:
    """Find Python files in repo that import/use the given package."""
    files_with_package = []

    if not os.path.exists(repo_path):
        return files_with_package

    # Search for Python files
    for root, dirs, files in os.walk(repo_path):
        # Skip common directories
        dirs[:] = [d for d in dirs if d not in ['__pycache__', '.git', 'node_modules', '.venv', 'venv']]

        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Check for imports
                    import_patterns = [
                        rf'^\s*import\s+{re.escape(package_name)}',
                        rf'^\s*from\s+{re.escape(package_name)}\s+import',
                        rf'^\s*import\s+.*\b{re.escape(package_name)}\b',
                    ]

                    for pattern in import_patterns:
                        if re.search(pattern, content, re.MULTILINE):
                            files_with_package.append(file_path)
                            break

                except Exception:
                    continue

    return files_with_package


# ---------------------------------------------------------------
# Database Import Functions
# ---------------------------------------------------------------

def get_or_create_project_id(cursor, repo):
    """Get or create project ID by repo URL."""
    cursor.execute("SELECT p_id FROM projects WHERE repo = %s", (repo,))
    row = cursor.fetchone()

    if row:
        return row[0]

    cursor.execute("INSERT INTO projects (repo) VALUES (%s)", (repo,))
    return cursor.lastrowid


def import_vulnerability_data_to_db(repo_url, risk_summaries=None):
    """Import vulnerability data from vulnerability_report.json to database."""
    try:
        # Check if database environment variables are configured
        db_host = os.environ.get("MYSQL_HOST")
        db_user = os.environ.get("MYSQL_USER")
        db_pass = os.environ.get("MYSQL_PASS")
        db_name = os.environ.get("MYSQL_DB")

        if not all([db_host, db_user, db_pass, db_name]):
            print("⚠️  Database configuration incomplete. Skipping database import.")
            print("   Required environment variables: MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DB")
            return

        print(f"🔌 Connecting to database: {db_host}")

        # Connect to MySQL using environment variables
        conn = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_pass,
            database=db_name,
            connection_timeout=30
        )
        cursor = conn.cursor()

        # Get project ID
        p_id = get_or_create_project_id(cursor, repo_url)

        # Clean existing rows for this project to avoid duplicates when unique keys are missing
        cursor.execute("DELETE FROM package_vulnerabilities WHERE p_id = %s", (p_id,))
        cursor.execute("DELETE FROM packages WHERE p_id = %s", (p_id,))

        # Load vulnerability report
        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_file = os.path.join(script_dir, "vulnerability_report.json")

        with open(json_file, "r") as f:
            data = json.load(f)

        # SQL queries
        package_upsert = """
            INSERT INTO packages (p_id, name, ecosystem, purl, version)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                version = VALUES(version),
                ecosystem = VALUES(ecosystem),
                purl = VALUES(purl)
        """

        vuln_upsert = """
            INSERT INTO vulnerabilities (v_id, published, modified, summary, details, severity)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                published = VALUES(published),
                modified = VALUES(modified),
                summary = VALUES(summary),
                details = VALUES(details),
                severity = VALUES(severity)
        """

        pkg_vuln_upsert = """
            INSERT INTO package_vulnerabilities (p_id, v_id, package_name, version, fixed_in, risk_summary)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                fixed_in = VALUES(fixed_in),
                risk_summary = VALUES(risk_summary)
        """

        # Process vulnerabilities grouped by package name
        vulnerabilities_data = data.get("vulnerabilities", {})

        for package_name, vuln_list in vulnerabilities_data.items():
            for vuln in vuln_list:
                v_id = vuln["id"]
                published = vuln.get("published")
                modified = vuln.get("modified")
                summary = vuln.get("summary")
                details = vuln.get("details")
                severity = vuln.get("database_specific", {}).get("severity", "UNKNOWN")

                # Insert vulnerability
                cursor.execute(vuln_upsert, (
                    v_id,
                    published,
                    modified,
                    summary,
                    details,
                    severity
                ))

                # Process affected packages for this vulnerability
                for affected in vuln.get("affected", []):
                    pkg_info = affected.get("package", {})
                    pkg_name = pkg_info.get("name")
                    pkg_eco = pkg_info.get("ecosystem")
                    purl = pkg_info.get("purl")

                    # Get version from extracted_packages.txt if available
                    pkg_version = None
                    try:
                        with open(os.path.join(script_dir, "extracted_packages.txt"), "r") as f:
                            for line in f:
                                if line.strip().startswith(f"{pkg_name}=="):
                                    pkg_version = line.strip().split("==")[1]
                                    break
                    except FileNotFoundError:
                        pass

                    # Insert package if we have the necessary info
                    if pkg_name and pkg_eco:
                        cursor.execute(package_upsert, (
                            p_id,
                            pkg_name,
                            pkg_eco,
                            purl,
                            pkg_version
                        ))

                        # Determine fixed version (if any)
                        fixed_in = None
                        for r in affected.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    fixed_in = event["fixed"]
                                    break
                            if fixed_in:
                                break

                        # Get risk summary for this package-vulnerability combination
                        risk_summary = None
                        if risk_summaries:
                            package_data = risk_summaries.get(pkg_name, {})
                            vuln_summaries = package_data.get("vulnerabilities", {})
                            if v_id in vuln_summaries:
                                risk_summary = vuln_summaries[v_id].get("summary")
                            else:
                                # Backward compatibility with older per-package summaries
                                risk_summary = package_data.get("summary")

                        # Insert package-vulnerability link
                        cursor.execute(pkg_vuln_upsert, (
                            p_id,
                            v_id,
                            pkg_name,
                            pkg_version,
                            fixed_in,
                            risk_summary
                        ))

        # Commit and close
        conn.commit()
        cursor.close()
        conn.close()

        print("\n✅ Database import completed successfully!")
        print(f"   Repository: {repo_url}")
        print("   Data imported to: oss_vuln database")

    except Exception as e:
        print(f"\n⚠️  Database import failed: {e}")
        print("   Vulnerability report is still available locally")


def main():
    """Main function to extract and display packages."""
    
    parser = argparse.ArgumentParser(
        description="Extract all open source packages from Python files and Jupyter notebooks, check versions, and scan for vulnerabilities"
    )
    parser.add_argument(
        "--github",
        type=str,
        help="GitHub repository URL to clone and analyze (e.g., https://github.com/user/repo)"
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Path to a specific notebook or Python file to analyze"
    )
    parser.add_argument(
        "--dir",
        type=str,
        help="Path to a directory containing Python files and notebooks"
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Keep downloaded GitHub repository in local 'github_repos' directory (default: use temp directory)"
    )
    parser.add_argument(
        "--no-versions",
        action="store_true",
        help="Skip checking installed package versions"
    )
    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Skip vulnerability scanning (extract packages only)"
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Skip database import (keep data local only)"
    )
    parser.add_argument(
        "--from-extracted",
        type=str,
        nargs='?',
        const='default',
        help="Load packages from extracted_packages.txt and scan for vulnerabilities"
    )
    
    args = parser.parse_args()
    
    # Handle --from-extracted flag (load from file and scan)
    if args.from_extracted:
        extracted_file = None
        if args.from_extracted != 'default':
            extracted_file = Path(args.from_extracted)
        packages = load_packages_from_extracted_file(extracted_file)
        
        if not packages:
            return
        
        # Convert to format needed for vulnerability scanning
        packages_with_versions = {
            pkg: (ver, ver != "NOT INSTALLED" and ver != "UNKNOWN")
            for pkg, ver in packages.items()
        }
        
        # Scan vulnerabilities
        print(f"📦 Loaded {len(packages)} packages from extracted_packages.txt\n")
        vulnerabilities = scan_all_packages_vulnerabilities(packages_with_versions)
        display_vulnerabilities(vulnerabilities)
        vuln_report = save_vulnerability_report(vulnerabilities)
        
        # Import to database (unless --no-db)
        if not args.no_db:
            print("\n" + "=" * 70)
            print("💾 IMPORTING DATA TO DATABASE")
            print("=" * 70)
            
            import_vulnerability_data_to_db("from-extracted-file")
        else:
            print("\n⏭️  Database import skipped (--no-db flag used)")
        
        # Generate risk summaries
        print("\n" + "=" * 70)
        print("🤖 GENERATING RISK SUMMARIES")
        print("=" * 70)
        
        try:
            risk_summaries = {}
            for package_name, vuln_list in vulnerabilities.items():
                if vuln_list:
                    file_context = f"Package {package_name} loaded from extracted_packages.txt"
                    risk_summaries[package_name] = {
                        "vulnerabilities": {},
                        "files": [],
                        "vulnerabilities_count": len(vuln_list)
                    }
                    for vuln in vuln_list:
                        vuln_id = vuln.get("id") or "UNKNOWN_ID"
                        summary = generate_risk_summary(package_name, [vuln], file_context)
                        risk_summaries[package_name]["vulnerabilities"][vuln_id] = {
                            "summary": summary,
                            "files": []
                        }
            
            if risk_summaries:
                # Save risk summaries
                risk_file = Path(__file__).parent / "risk_summaries.json"
                with open(risk_file, 'w') as f:
                    json.dump(risk_summaries, f, indent=2)
                
                print(f"💾 Risk summaries saved to: {risk_file}")
                print(f"   Generated summaries for {len(risk_summaries)} vulnerable packages")
            else:
                print("ℹ️  No vulnerable packages found, skipping risk summary generation")
                
        except Exception as e:
            print(f"⚠️  Risk summary generation failed: {e}")
            print("   Vulnerability analysis still available")
        
        return
    
    all_packages = set()
    source = ""
    repo_path = None
    temp_dir = None
    check_versions = not args.no_versions
    
    try:
        if args.github:
            # Clone GitHub repo and analyze
            repo_path = clone_github_repo(args.github, keep_local=args.keep)
            if repo_path:
                all_packages = extract_packages_from_directory(repo_path)
                source = f"GitHub Repository: {args.github}"
                if not args.keep:
                    temp_dir = repo_path
        
        elif args.dir:
            # Analyze directory
            all_packages = extract_packages_from_directory(args.dir)
            repo_path = args.dir
            source = f"Directory: {args.dir}"
        
        elif args.file:
            # Analyze specific file
            file_path = Path(args.file)
            if not file_path.exists():
                print(f"❌ File not found: {file_path}")
                return
            
            print(f"📄 Analyzing file: {file_path.name}\n")
            
            if file_path.suffix == ".ipynb":
                all_packages = extract_packages_from_notebook(str(file_path))
            elif file_path.suffix == ".py":
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                    all_packages = extract_imports_from_code(code)
            
            repo_path = str(file_path)
            source = f"File: {file_path.name}"
        
        else:
            # Default: analyze local notebook
            notebook_path = Path(__file__).parent / "Group 3 - ISBA 2403 - M8 Homework Assignment.ipynb"
            
            if not notebook_path.exists():
                print(f"❌ Notebook file not found: {notebook_path}")
                print("\nUsage:")
                print("  python extract_packages.py                          # Analyze local notebook + scan")
                print("  python extract_packages.py --github <URL>          # Clone GitHub repo + scan")
                print("  python extract_packages.py --github <URL> --keep   # Keep downloaded repo")
                print("  python extract_packages.py --file path/to/file.py  # Analyze file + scan")
                print("  python extract_packages.py --dir path/to/dir       # Analyze directory + scan")
                print("  python extract_packages.py --no-scan               # Extract only (no scan)")
                print("  python extract_packages.py --from-extracted        # Scan from extracted_packages.txt")
                print("\nOutput files: extracted_packages.txt, vulnerability_report.json")
                return
            
            print(f"📖 Analyzing notebook: {notebook_path.name}\n")
            all_packages = extract_packages_from_notebook(str(notebook_path))
            repo_path = str(notebook_path)
            source = f"Notebook: {notebook_path.name}"
        
        # Display results if packages found
        if all_packages:
            third_party, installed_versions = display_results(all_packages, source, repo_path, check_versions=check_versions)
            
            # Scan for vulnerabilities (DEFAULT BEHAVIOR - unless --no-scan is used)
            if not args.no_scan and check_versions and third_party:
                print("\n" + "=" * 70)
                print("🔍 SCANNING FOR VULNERABILITIES (OSV.dev)")
                print("=" * 70 + "\n")
                
                vulnerabilities = scan_all_packages_vulnerabilities(installed_versions)
                display_vulnerabilities(vulnerabilities)
                vuln_report = save_vulnerability_report(vulnerabilities)
                
                # Enrich with missing fields from OSV.dev API
                print("\n" + "=" * 70)
                print("✨ ENRICHING REPORT WITH MISSING FIELDS FROM OSV.dev")
                print("=" * 70 + "\n")
                
                # Enrich the vulnerability report directly
                try:
                    enriched_report = enrich_vulnerability_report(vuln_report)
                    
                    # Save enriched report
                    enriched_file = Path(__file__).parent / "vulnerability_report_enriched.json"
                    with open(enriched_file, 'w') as f:
                        json.dump(enriched_report, f, indent=2, default=str)
                    
                    print(f"💾 Enriched report saved to: {enriched_file}")
                    
                    # Generate and save summary
                    summary = generate_enrichment_summary(vuln_report, enriched_report)
                    summary_file = Path(__file__).parent / "enrichment_summary.txt"
                    with open(summary_file, 'w') as f:
                        f.write(summary)
                    
                    print(f"💾 Summary saved to: {summary_file}")
                    print("\n✅ Vulnerability report enriched successfully!")
                    print("   - Added missing fields: schema_version, database_specific.source")
                    
                    # Generate risk summaries BEFORE database import
                    print("\n" + "=" * 70)
                    print("🤖 GENERATING RISK SUMMARIES")
                    print("=" * 70)
                    
                    risk_summaries = {}
                    try:
                        # Load the enriched vulnerability report
                        with open(enriched_file, 'r') as f:
                            vuln_data = json.load(f)
                        
                        # Get repo path for file analysis
                        repo_path = None
                        if args.github and temp_dir:
                            repo_path = temp_dir  # Use the cloned repo path
                        elif args.dir:
                            repo_path = args.dir
                        elif not args.github and not args.dir and not args.file:
                            repo_path = Path(__file__).parent
                        
                        if repo_path:
                            risk_summaries = generate_all_risk_summaries(str(repo_path), vuln_data)
                            
                            # Save risk summaries
                            risk_file = Path(__file__).parent / "risk_summaries.json"
                            with open(risk_file, 'w') as f:
                                json.dump(risk_summaries, f, indent=2)
                            
                            print(f"💾 Risk summaries saved to: {risk_file}")
                            print(f"   Generated summaries for {len(risk_summaries)} vulnerable packages")
                        else:
                            print("⚠️  Could not determine repository path for risk summary generation")
                            
                    except Exception as e:
                        print(f"⚠️  Risk summary generation failed: {e}")
                        print("   Proceeding with database import without risk summaries")
                    
                    # Import data to database (unless --no-db is used)
                    if not args.no_db:
                        print("\n" + "=" * 70)
                        print("💾 IMPORTING DATA TO DATABASE")
                        print("=" * 70)

                        print(risk_summaries)
                        print()
                        print()
                        # Get repo URL for database import
                        repo_url = args.github if args.github else "local-analysis"
                        import_vulnerability_data_to_db(repo_url, risk_summaries)
                    else:
                        print("\n⏭️  Database import skipped (--no-db flag used)")
                    
                except Exception as e:
                    print(f"⚠️  Enrichment failed, but original report is still valid")
                    print(f"   Error: {e}")
                    print("   Original vulnerability_report.json is still available")
                    
                    # Still import the original vulnerability report to database (unless --no-db)
                    if not args.no_db:
                        print("\n" + "=" * 70)
                        print("💾 IMPORTING ORIGINAL DATA TO DATABASE")
                        print("=" * 70)
                        
                        repo_url = args.github if args.github else "local-analysis"
                        import_vulnerability_data_to_db(repo_url)
                    else:
                        print("\n⏭️  Database import skipped (--no-db flag used)")
                    
                    # Generate risk summaries with original report
                    print("\n" + "=" * 70)
                    print("🤖 GENERATING RISK SUMMARIES")
                    print("=" * 70)
                    
                    try:
                        # Load the original vulnerability report
                        vuln_file = Path(__file__).parent / "vulnerability_report.json"
                        with open(vuln_file, 'r') as f:
                            vuln_data = json.load(f)
                        
                        # Get repo path for file analysis
                        repo_path = None
                        if args.github and temp_dir:
                            repo_path = temp_dir
                        elif args.dir:
                            repo_path = args.dir
                        elif not args.github and not args.dir and not args.file:
                            repo_path = Path(__file__).parent
                        
                        if repo_path:
                            risk_summaries = generate_all_risk_summaries(str(repo_path), vuln_data)
                            
                            # Save risk summaries
                            risk_file = Path(__file__).parent / "risk_summaries.json"
                            with open(risk_file, 'w') as f:
                                json.dump(risk_summaries, f, indent=2)
                            
                            print(f"💾 Risk summaries saved to: {risk_file}")
                            print(f"   Generated summaries for {len(risk_summaries)} vulnerable packages")
                        else:
                            print("⚠️  Could not determine repository path for risk summary generation")
                            
                    except Exception as e:
                        print(f"⚠️  Risk summary generation failed: {e}")
                        print("   Vulnerability analysis still available")
            elif args.no_scan:
                print("\n⏭️  Vulnerability scanning skipped (--no-scan flag used)")
        else:
            print("⚠️  No packages found.")
    
    finally:
        # Clean up temporary directory only if not keeping it
        if temp_dir and Path(temp_dir).exists():
            print(f"\n🧹 Cleaning up temporary directory: {temp_dir}")
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    main()
