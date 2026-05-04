import re
import os

class NmapProbes:
    def __init__(self, probes_path=None):
        if probes_path is None:
            probes_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'nmap-service-probes')
        self.probes_path = probes_path
        self.patterns = []
        self._load()
        
    def _load(self):
        if not os.path.exists(self.probes_path):
            return
            
        with open(self.probes_path, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith('match '):
                    parts = line.split(maxsplit=2)
                    if len(parts) < 3: continue
                    protocol = parts[1]
                    rest = parts[2]
                    
                    # parse m|pattern|flags
                    if not rest.startswith('m'): continue
                    sep = rest[1]
                    end_idx = rest.find(sep, 2)
                    if end_idx == -1: continue
                    
                    pattern = rest[2:end_idx]
                    
                    # try to extract flags
                    flags_end = end_idx + 1
                    while flags_end < len(rest) and rest[flags_end] in 'is':
                        flags_end += 1
                        
                    flags_str = rest[end_idx+1:flags_end]
                    
                    re_flags = 0
                    if 'i' in flags_str: re_flags |= re.I
                    if 's' in flags_str: re_flags |= re.S
                    
                    try:

                        pattern = pattern.replace('(?=', '(?:') # replace lookaheads just in case
                        
                        compiled = re.compile(pattern, re_flags)
                    except:
                        continue
                        
                    version_info = rest[flags_end:].strip()
                    
                    product = None
                    version = None
                    
                    p_match = re.search(r'p/([^/]+)/', version_info)
                    if p_match: product = p_match.group(1)
                    
                    # v/version/
                    v_match = re.search(r'v/([^/]+)/', version_info)
                    if v_match: version = v_match.group(1)
                    
                    if product:
                        self.patterns.append({
                            'regex': compiled,
                            'product': product,
                            'version': version
                        })

    def parse_banner(self, banner):
        if not banner: return None
        
        if not banner.endswith('\n'):
            banner += '\r\n\r\n'
            
        for p in self.patterns:
            m = p['regex'].search(banner)
            if m:
                prod = p['product']
                ver = p['version']
                
                if ver and '$' in ver:
                    for i, group in enumerate(m.groups(), start=1):
                        if group:
                            ver = ver.replace(f'${i}', group)
                    ver = re.sub(r'\$\d+', '', ver).strip()
                
                if prod and '$' in prod:
                    for i, group in enumerate(m.groups(), start=1):
                        if group:
                            prod = prod.replace(f'${i}', group)
                    prod = re.sub(r'\$\d+', '', prod).strip()
                
                if ver:
                    ver = ver.split()[0]
                    return f"{prod} {ver}"
                return prod
                
        return None
