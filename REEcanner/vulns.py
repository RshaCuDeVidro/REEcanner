"""Vulnerability lookup via searchsploit (ExploitDB)"""
import subprocess
import json
import re
import sys
import shutil
import functools

def has_searchsploit():
    """Check if searchsploit is available"""
    return shutil.which('searchsploit') is not None

_nmap_parser = None

def get_nmap_parser():
    global _nmap_parser
    if _nmap_parser is None:
        try:
            from REEcanner.nmap_probes import NmapProbes
            _nmap_parser = NmapProbes()
        except: pass
    return _nmap_parser

def parse_banner(banner, port=None):
    """Extract software name + version from a banner string"""
    if not banner:
        return None
    
    parser = get_nmap_parser()
    parsed = None
    if parser:
        parsed = parser.parse_banner(banner)
        
    if parsed:
        return parsed

    # generic: try to extract "Name/Version" pattern
    # skip protocol version strings like HTTP/1.1, HTTP/2, SMTP, etc
    SKIP = {'HTTP', 'SMTP', 'ESMTP', 'FTP', 'IMAP', 'POP3', 'SIP', 'RTSP', 'IRC', 'SSH'}
    # Improved regex: supports name/version, name version, and version with more segments
    m = re.search(r'([A-Za-z][\w.-]{2,})[/\s](\d+\.\d+(?:[\d.]+)?)', banner)
    if m and m.group(1).upper() not in SKIP:
        return f"{m.group(1)} {m.group(2)}"
    
    return None

# Softwares que vale a pena buscar mesmo sem versão (com cautela)
HIGH_RISK_SOFTWARE = {'DRUPAL', 'WORDPRESS', 'JOOMLA', 'MAGENTO', 'EXCHANGE', 'SHAREPOINT', 'COLDFUSION', 'GITLAB'}

@functools.lru_cache(maxsize=1024)
def searchsploit_query(query, max_results=5):
    """Run searchsploit and return parsed results"""
    if not query or not has_searchsploit():
        return []
    try:
        result = subprocess.run(
            ['searchsploit', '--json', '-t', query],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout)
        exploits = []
        for e in data.get('RESULTS_EXPLOIT', [])[:max_results]:
            exploit = {
                'id': f"EDB-{e.get('EDB-ID', '?')}",
                'title': e.get('Title', ''),
                'path': e.get('Path', ''),
            }
            cves = re.findall(r'CVE-\d{4}-\d+', exploit['title'], re.I)
            if cves:
                exploit['cve'] = cves[0]
            exploits.append(exploit)
        return exploits
    except:
        return []

def lookup_vulns(banner, port=None, server=None):
    queries = []
    
    def add_query(raw):
        parsed = parse_banner(raw, port)
        if parsed:
            queries.append(parsed)
        else:
            # Fallback: if it matches high risk software exactly, query it
            clean = re.sub(r'[^A-Za-z0-9]', '', str(raw)).upper()
            if clean in HIGH_RISK_SOFTWARE:
                queries.append(raw.strip())

    if server: add_query(server)
    if banner: add_query(banner)
    
    # dedupe queries
    queries = list(dict.fromkeys(queries))
    
    all_exploits = []
    seen_ids = set()
    for q in queries:
        for e in searchsploit_query(q):
            if e['id'] not in seen_ids:
                seen_ids.add(e['id'])
                all_exploits.append(e)
    
    return all_exploits
