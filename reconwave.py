#!/usr/bin/env python3
"""
RECONWAVE - Asynchronous Attack-Surface Recon Engine
Continuous subdomain monitoring with asset graph, diffing, and alerts.
Author: nadirzhon | github.com/nadirzhon/reconwave
"""

import asyncio
import json
import argparse
import sqlite3
import hashlib
import ssl
import socket
from datetime import datetime
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path

try:
    import aiohttp
    import dns.asyncresolver
except ImportError:
    aiohttp = None

DB_FILE = "reconwave.db"

# ─────────────────────────────────────────────────────────────────────────────
# PASSIVE SUBDOMAIN SOURCES (free, no API key)
# ─────────────────────────────────────────────────────────────────────────────
async def from_crtsh(session, domain):
    """Certificate transparency logs."""
    subs = set()
    try:
        async with session.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                data = await r.json()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(domain) and " " not in name:
                            subs.add(name)
    except Exception:
        pass
    return subs

async def from_hackertarget(session, domain):
    """HackerTarget hostsearch."""
    subs = set()
    try:
        async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                text = await r.text()
                for line in text.splitlines():
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(domain):
                        subs.add(host)
    except Exception:
        pass
    return subs

async def from_rapiddns(session, domain):
    """RapidDNS passive DNS."""
    subs = set()
    try:
        async with session.get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status == 200:
                text = await r.text()
                import re
                for m in re.finditer(rf"([a-zA-Z0-9._-]+\.{re.escape(domain)})", text):
                    subs.add(m.group(1).lower())
    except Exception:
        pass
    return subs

# ─────────────────────────────────────────────────────────────────────────────
# ACTIVE RESOLUTION & PROBING
# ─────────────────────────────────────────────────────────────────────────────
async def resolve_host(resolver, host):
    """Resolve A record."""
    try:
        answers = await resolver.resolve(host, "A")
        return host, [str(a) for a in answers]
    except Exception:
        return host, []

async def probe_http(session, host):
    """Check if host serves HTTP/HTTPS, grab title + server."""
    for scheme in ("https", "http"):
        try:
            async with session.get(f"{scheme}://{host}", timeout=aiohttp.ClientTimeout(total=8),
                                   allow_redirects=True, ssl=False) as r:
                text = await r.text(errors="ignore")
                import re
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                if m:
                    title = m.group(1).strip()[:80]
                return {
                    "host": host, "scheme": scheme, "status": r.status,
                    "server": r.headers.get("Server", ""),
                    "title": title,
                    "tech": detect_tech(text, dict(r.headers)),
                    "content_length": len(text),
                }
        except Exception:
            continue
    return None

def detect_tech(html, headers):
    """Lightweight technology fingerprinting."""
    tech = []
    signatures = {
        "WordPress": ["wp-content", "wp-includes"],
        "React": ["react", "_reactRootContainer", "__NEXT_DATA__"],
        "Vue.js": ["vue.js", "__vue__", "data-v-"],
        "Angular": ["ng-version", "angular"],
        "Next.js": ["__NEXT_DATA__", "/_next/"],
        "Laravel": ["laravel_session", "XSRF-TOKEN"],
        "Django": ["csrfmiddlewaretoken", "__admin__"],
        "Cloudflare": [],
        "nginx": [],
        "Apache": [],
    }
    html_l = html.lower()
    for name, sigs in signatures.items():
        if any(s.lower() in html_l for s in sigs):
            tech.append(name)
    # Header-based
    server = headers.get("Server", "").lower()
    if "nginx" in server: tech.append("nginx")
    if "apache" in server: tech.append("Apache")
    if "cloudflare" in server or "cf-ray" in [k.lower() for k in headers]: tech.append("Cloudflare")
    if headers.get("X-Powered-By"): tech.append(headers["X-Powered-By"])
    return list(set(tech))

# ─────────────────────────────────────────────────────────────────────────────
# ASSET GRAPH
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class AssetGraph:
    domain: str
    subdomains: dict = field(default_factory=dict)   # host -> {ips, http, ...}
    ip_map: dict = field(default_factory=lambda: defaultdict(list))  # ip -> [hosts]

    def add(self, host, ips, http_info=None):
        self.subdomains[host] = {"ips": ips, "http": http_info}
        for ip in ips:
            self.ip_map[ip].append(host)

    def shared_hosting(self):
        """IPs hosting multiple subdomains — pivot points."""
        return {ip: hosts for ip, hosts in self.ip_map.items() if len(hosts) > 1}

# ─────────────────────────────────────────────────────────────────────────────
# DATABASE + DIFFING
# ─────────────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""CREATE TABLE IF NOT EXISTS assets (
        domain TEXT, host TEXT, ips TEXT, http_status INT, title TEXT,
        tech TEXT, first_seen TEXT, last_seen TEXT,
        PRIMARY KEY (domain, host))""")
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        domain TEXT, scan_time TEXT, total_subs INT, new_subs INT)""")
    conn.commit()
    return conn

def diff_and_store(conn, graph: AssetGraph):
    """Compare against last scan, return newly discovered subdomains."""
    now = datetime.utcnow().isoformat()
    existing = set(r[0] for r in conn.execute(
        "SELECT host FROM assets WHERE domain=?", (graph.domain,)).fetchall())
    current = set(graph.subdomains.keys())
    new_subs = current - existing

    for host, info in graph.subdomains.items():
        ips = ",".join(info["ips"])
        http = info.get("http") or {}
        conn.execute("""INSERT INTO assets VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(domain,host) DO UPDATE SET last_seen=?, ips=?, http_status=?""",
            (graph.domain, host, ips, http.get("status",0), http.get("title",""),
             ",".join(http.get("tech",[])), now, now, now, ips, http.get("status",0)))
    conn.execute("INSERT INTO scans VALUES (?,?,?,?)",
                 (graph.domain, now, len(current), len(new_subs)))
    conn.commit()
    return new_subs

# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────
async def recon(domain, resolve=True, probe=True):
    print(f"\n[RECONWAVE] Target: {domain}")
    graph = AssetGraph(domain=domain)

    async with aiohttp.ClientSession(headers={"User-Agent":"Mozilla/5.0 (RECONWAVE)"}) as session:
        # 1. Passive enumeration (parallel sources)
        print("[*] Passive enumeration...")
        source_results = await asyncio.gather(
            from_crtsh(session, domain),
            from_hackertarget(session, domain),
            from_rapiddns(session, domain),
        )
        all_subs = set()
        for s in source_results:
            all_subs |= s
        print(f"[+] {len(all_subs)} unique subdomains from passive sources")

        if not all_subs:
            print("[-] No subdomains found")
            return graph

        # 2. Active resolution (parallel, throttled)
        if resolve:
            print("[*] Resolving DNS...")
            resolver = dns.asyncresolver.Resolver()
            resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
            sem = asyncio.Semaphore(50)
            async def bounded_resolve(h):
                async with sem:
                    return await resolve_host(resolver, h)
            resolved = await asyncio.gather(*[bounded_resolve(h) for h in all_subs])
            live = {h: ips for h, ips in resolved if ips}
            print(f"[+] {len(live)} subdomains resolve to an IP")
        else:
            live = {h: [] for h in all_subs}

        # 3. HTTP probing (parallel, throttled)
        if probe and live:
            print("[*] Probing HTTP services...")
            sem = asyncio.Semaphore(30)
            async def bounded_probe(h):
                async with sem:
                    return await probe_http(session, h)
            probed = await asyncio.gather(*[bounded_probe(h) for h in live])
            http_map = {p["host"]: p for p in probed if p}
            print(f"[+] {len(http_map)} live HTTP services")
        else:
            http_map = {}

        # 4. Build graph
        for host, ips in live.items():
            graph.add(host, ips, http_map.get(host))

    return graph


def print_report(graph: AssetGraph, new_subs):
    print(f"\n{'='*60}")
    print(f"  RECONWAVE — {graph.domain}")
    print(f"{'='*60}")
    print(f"  Total subdomains: {len(graph.subdomains)}")
    print(f"  Live HTTP: {sum(1 for s in graph.subdomains.values() if s.get('http'))}")

    if new_subs:
        print(f"\n  🆕 NEW SINCE LAST SCAN ({len(new_subs)})")
        for s in sorted(new_subs)[:20]:
            print(f"    + {s}")

    shared = graph.shared_hosting()
    if shared:
        print(f"\n  🔗 SHARED HOSTING (pivot points)")
        for ip, hosts in list(shared.items())[:5]:
            print(f"    {ip} → {len(hosts)} hosts: {', '.join(hosts[:3])}...")

    # Interesting subdomains
    interesting_kw = ["admin","dev","staging","test","api","internal","vpn","git","jenkins","jira","dashboard","portal","beta"]
    interesting = [h for h in graph.subdomains if any(kw in h for kw in interesting_kw)]
    if interesting:
        print(f"\n  🎯 HIGH-VALUE TARGETS")
        for h in interesting[:15]:
            http = graph.subdomains[h].get("http") or {}
            status = http.get("status", "—")
            tech = ",".join(http.get("tech", []))
            print(f"    {h} [{status}] {tech}")


def main():
    parser = argparse.ArgumentParser(description="RECONWAVE — Attack Surface Recon Engine")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("-o", "--output", help="JSON output file")
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution")
    parser.add_argument("--no-probe", action="store_true", help="Skip HTTP probing")
    parser.add_argument("--monitor", action="store_true", help="Store scan for diffing")
    args = parser.parse_args()

    if aiohttp is None:
        print("[!] Install dependencies: pip install aiohttp dnspython")
        return

    graph = asyncio.run(recon(args.domain, resolve=not args.no_resolve, probe=not args.no_probe))

    new_subs = set()
    if args.monitor:
        conn = init_db()
        new_subs = diff_and_store(conn, graph)

    print_report(graph, new_subs)

    if args.output:
        out = {
            "domain": graph.domain,
            "scan_time": datetime.utcnow().isoformat(),
            "subdomains": graph.subdomains,
            "shared_hosting": graph.shared_hosting(),
            "new_subdomains": list(new_subs),
        }
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"\n[*] Report saved to {args.output}")


if __name__ == "__main__":
    main()
