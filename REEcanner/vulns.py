"""Vulnerability lookup via searchsploit (ExploitDB)"""
import subprocess
import json
import re
import sys
import shutil

def has_searchsploit():
    """Check if searchsploit is available"""
    return shutil.which('searchsploit') is not None

def parse_banner(banner, port=None):
    """Extract software name + version from a banner string"""
    if not banner:
        return None
    
    # SSH: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
    m = re.search(r'OpenSSH[_\s](\d+\.\d+\S*)', banner, re.I)
    if m: return f"OpenSSH {m.group(1).replace('p', ' p')}"
    
    # Apache: Server: Apache/2.4.49 or Apache/2.4.49 (Unix)
    m = re.search(r'Apache[/\s](\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"Apache {m.group(1)}"
    
    # nginx: Server: nginx/1.18.0
    m = re.search(r'nginx[/\s](\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"nginx {m.group(1)}"
    
    # vsftpd: 220 (vsFTPd 3.0.3)
    m = re.search(r'vsFTPd\s+(\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"vsftpd {m.group(1)}"
    
    # ProFTPD: 220 ProFTPD 1.3.5 Server
    m = re.search(r'ProFTPD\s+(\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"ProFTPD {m.group(1)}"
    
    # Pure-FTPd
    m = re.search(r'Pure-FTPd', banner, re.I)
    if m: return "Pure-FTPd"
    
    # Microsoft IIS: Server: Microsoft-IIS/10.0
    m = re.search(r'Microsoft-IIS[/\s](\d+\.\d+)', banner, re.I)
    if m: return f"Microsoft IIS {m.group(1)}"
    
    # Postfix SMTP
    m = re.search(r'Postfix', banner, re.I)
    if m: return "Postfix"
    
    # Exim SMTP: 220 mail.x.com ESMTP Exim 4.94.2
    m = re.search(r'Exim\s+(\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"Exim {m.group(1)}"
    
    # Dovecot: * OK [CAPABILITY ...] Dovecot ready.
    m = re.search(r'Dovecot', banner, re.I)
    if m: return "Dovecot"
    
    # MySQL: 5.7.38-0ubuntu0.18.04.1
    m = re.search(r'(\d+\.\d+\.\d+).*MariaDB', banner, re.I)
    if m: return f"MariaDB {m.group(1)}"
    m = re.search(r'mysql.*?(\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"MySQL {m.group(1)}"
    
    # Tomcat
    m = re.search(r'Tomcat[/\s](\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"Apache Tomcat {m.group(1)}"
    
    # PHP
    m = re.search(r'PHP[/\s](\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"PHP {m.group(1)}"
    
    # LiteSpeed
    m = re.search(r'LiteSpeed[/\s](\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"LiteSpeed {m.group(1)}"
    
    # Jetty
    m = re.search(r'Jetty[/()\s](\d+\.\d+\.\d+)', banner, re.I)
    if m: return f"Jetty {m.group(1)}"

    # generic: try to extract "Name/Version" pattern
    # blacklist protocol/generic words que geram lixo no searchsploit
    _blacklist = {'HTTP', 'HTTPS', 'SMTP', 'ESMTP', 'FTP', 'IMAP', 'POP3', 'OK', 'Content', 'Date', 'Server', 'Connection', 'Transfer', 'Accept', 'Cache', 'X', 'Set'}
    m = re.search(r'([A-Za-z][\w.-]+)[/\s](\d+\.\d+(?:\.\d+)?)', banner)
    if m and m.group(1) not in _blacklist and len(m.group(1)) > 2:
        return f"{m.group(1)} {m.group(2)}"
    
    return None

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
    if server:
        parsed = parse_banner(server, port)
        if parsed:
            queries.append(parsed)
    if banner:
        parsed = parse_banner(banner, port)
        if parsed and parsed not in queries:
            queries.append(parsed)
    
    all_exploits = []
    seen_ids = set()
    for q in queries:
        for e in searchsploit_query(q):
            if e['id'] not in seen_ids:
                seen_ids.add(e['id'])
                all_exploits.append(e)
    
    return all_exploits
