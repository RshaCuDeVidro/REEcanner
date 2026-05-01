import ipaddress
import random
import bisect
from typing import List, Set

def parse_ports_list(port_string: str) -> list[int]:
    ports = set()
    for part in port_string.split(','):
        part = part.strip()
        if not part:
            continue
        
        if '-' in part:
            try:
                start_str, end_str = part.split('-', 1)
                start, end = int(start_str), int(end_str)
            except ValueError:
                raise ValueError(f"invalid port range format: {part}")
            
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"ports out of bounds in range: {part}")
            if start > end:
                raise ValueError(f"start port greater than end port: {part}")
                
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"invalid port number: {part}")
                
            if not (1 <= port <= 65535):
                raise ValueError(f"port out of bounds: {port}")
            ports.add(port)
            
    return sorted(list(ports))

class FeistelShuffler:
    def __init__(self, key: int, max_val: int = 0xFFFFFFFF):
        self.max_val = max_val
        self.seed = key
        self.keys = [(key >> (8 * i)) & 0xFFFFFFFF for i in range(4)]

        #bloco dinamico sizing, nao mexer da muito bug mesmo, trust me
        bits = max(2, (max_val - 1).bit_length()) if max_val > 1 else 2
        if bits % 2:
            bits += 1
        self.half_bits = bits // 2
        self.mask = (1 << self.half_bits) - 1

    def _round_function(self, r: int, k: int) -> int:
        val = (r ^ k) & self.mask
        val = (val * 0x41C64E6D) + 0x3039
        return (val ^ (val >> 8)) & self.mask

    def _encrypt(self, index: int) -> int:
        l = (index >> self.half_bits) & self.mask
        r = index & self.mask
        for i in range(4):
            l, r = r, l ^ self._round_function(r, self.keys[i])
        return (r << self.half_bits) | l

    def get(self, index: int) -> int:
        x = self._encrypt(index)
        while x >= self.max_val:
            x = self._encrypt(x)
        return x

class InclusionManager:
    def __init__(self, networks_list: List[str] = None, seed=None):
        self.networks = []
        if not networks_list or len(networks_list) == 0: 
            networks_list = ["0.0.0.0/0"]
        
        self.total_ips = 0
        for net_str in networks_list:
            try:
                net = ipaddress.IPv4Network(net_str.strip(), strict=False)
                size = net.num_addresses
                self.networks.append({
                    'net': int(net.network_address), 
                    'size': size, 
                    'start': self.total_ips
                })
                self.total_ips += size
            except: continue
            
        if not self.networks:
            self.networks.append({'net': 0, 'size': 0x100000000, 'start': 0})
            self.total_ips = 0x100000000
            
        self.starts = [n['start'] for n in self.networks]
        self.single_net = len(self.networks) == 1
        
        seed_val = seed if seed is not None else random.getrandbits(32)
        self.shuffler = FeistelShuffler(key=seed_val, max_val=self.total_ips)

    def get_random_ip_int(self, index: int) -> tuple:
        idx = self.shuffler.get(index % self.total_ips)
        if self.single_net:
            return self.networks[0]['net'] + idx, index
            
        i = bisect.bisect_right(self.starts, idx) - 1
        n = self.networks[i]
        return n['net'] + (idx - n['start']), index

DEFAULT_BLACKLIST = [
    "0.0.0.0/8",       # local
    "10.0.0.0/8",      # rfc1918
    "100.64.0.0/10",   # cgnat
    "127.0.0.0/8",     # loopback
    "169.254.0.0/16",  # link-local
    "172.16.0.0/12",   # rfc1918
    "192.0.0.0/24",    # ietf protocol
    "192.168.0.0/16",  # rfc1918
    "224.0.0.0/4",     # multicast
    "240.0.0.0/4",     # reserved
    "255.255.255.255/32" # broadcast
]

class BlacklistManager:
    def __init__(self, include_recommended: bool = True, allow_private: bool = False, custom_networks: List[str] = None):
        networks = []
        if custom_networks:
            networks.extend(custom_networks)
            
        if not allow_private:
            networks.extend(DEFAULT_BLACKLIST)
            
        if include_recommended:
            networks.extend(["148.59.85.0/24", 
                             "6.0.0.0/8", 
                             "7.0.0.0/8", 
                             "11.0.0.0/8", 
                             "21.0.0.0/8", 
                             "22.0.0.0/8", 
                             "26.0.0.0/8", 
                             "28.0.0.0/8", 
                             "29.0.0.0/8", 
                             "30.0.0.0/8", 
                             "33.0.0.0/8", 
                             "55.0.0.0/8", 
                             "214.0.0.0/8", 
                             "215.0.0.0/8"])
            
        ranges = []
        for cidr in networks:
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                ranges.append((int(net.network_address), int(net.broadcast_address)))
            except:
                pass
        
        ranges.sort()
        merged = []
        for start, end in ranges:
            if not merged:
                merged.append([start, end])
            else:
                last_start, last_end = merged[-1]
                if start <= last_end + 1:
                    merged[-1][1] = max(last_end, end)
                else:
                    merged.append([start, end])
                    
        self._flat_ranges = []
        for start, end in merged:
            self._flat_ranges.extend([start, end])

    def is_ip_int_public(self, ip_int: int) -> bool:
        idx = bisect.bisect_right(self._flat_ranges, ip_int)
        if idx % 2 == 1:
            return False
        if idx < len(self._flat_ranges) and self._flat_ranges[idx] == ip_int:
            return False
        return True
