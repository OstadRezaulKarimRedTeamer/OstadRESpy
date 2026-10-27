# -*- coding: utf-8 -*-
"""
====================================================================================================
               🌐 OstadRESpy Engine 4: Network Forensics & C2 Beaconing / DGA Hunter
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

import math
import re

def domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    entropy = 0.0
    for x in set(domain):
        p_x = domain.count(x) / len(domain)
        entropy -= p_x * math.log2(p_x)
    return entropy

def analyze_network_traffic(urls: list):
    res = {
        "dga_candidates": [],
        "dns_tunneling_candidates": [],
        "suspicious_tlds": [],
        "cloud_c2_endpoints": []
    }

    suspicious_tlds = ['.xyz', '.top', '.ru', '.onion', '.cc', '.su', '.work', '.click']
    c2_indicators = [
        'discord.com/api/webhooks',
        'api.telegram.org/bot',
        'ngrok.io',
        'duckdns.org',
        'pastebin.com/raw',
        'hastebin.com/raw',
        'raw.githubusercontent.com',
        'webhook.site',
        'transfer.sh'
    ]

    for u in urls:
        m = re.search(r'https?://([^/:\s]+)', u)
        if not m:
            continue
        host = m.group(1).lower()

        # DGA check (entropy > 3.6 on domain name)
        name_part = host.split('.')[0]
        if len(name_part) > 12 and domain_entropy(name_part) > 3.6:
            res["dga_candidates"].append(host)

        # DNS Tunneling (unusually long hostnames with high entropy)
        if len(host) > 50:
            res["dns_tunneling_candidates"].append(host)

        # TLD check
        for tld in suspicious_tlds:
            if host.endswith(tld):
                res["suspicious_tlds"].append(u)

        # Cloud C2 and Dead Drop Resolvers
        for c2 in c2_indicators:
            if c2 in u.lower():
                res["cloud_c2_endpoints"].append(u)

    res["dga_candidates"] = sorted(list(set(res["dga_candidates"])))
    res["dns_tunneling_candidates"] = sorted(list(set(res["dns_tunneling_candidates"])))
    res["suspicious_tlds"] = sorted(list(set(res["suspicious_tlds"])))
    res["cloud_c2_endpoints"] = sorted(list(set(res["cloud_c2_endpoints"])))

    return res
