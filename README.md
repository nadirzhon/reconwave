# RECONWAVE

Asynchronous attack-surface reconnaissance engine for bug bounty and red team.

RECONWAVE discovers a target's entire external attack surface, resolves and probes every asset in parallel, builds an asset relationship graph, and diffs results over time so you get alerted when new subdomains appear.

## Features

- Passive subdomain enumeration from multiple sources (crt.sh, HackerTarget, RapidDNS) — no API key
- Async DNS resolution and HTTP probing (hundreds of hosts in parallel via asyncio)
- Technology fingerprinting (WordPress, React, Next.js, Laravel, nginx, Cloudflare...)
- Asset graph: maps subdomain to IP to shared-hosting pivot points
- Continuous monitoring: stores scans in SQLite and diffs to surface NEW subdomains
- High-value target detection (admin, dev, staging, api, internal, jenkins, jira...)

## Quick Start

    git clone https://github.com/nadirzhon/reconwave
    cd reconwave
    pip install -r requirements.txt

    python reconwave.py -d target.com
    python reconwave.py -d target.com -o report.json
    python reconwave.py -d target.com --monitor   # store for diffing

## Continuous monitoring

Run on a cron to get alerted when a target exposes new infrastructure:

    # crontab: every 6 hours
    0 */6 * * * cd /path/reconwave && python reconwave.py -d target.com --monitor

New subdomains since the last scan are flagged in the output — often the freshest, least-tested attack surface.

## Example output

    ============================================================
      RECONWAVE - target.com
    ============================================================
      Total subdomains: 143
      Live HTTP: 89

      NEW SINCE LAST SCAN (3)
        + staging-v2.target.com
        + internal-api.target.com

      SHARED HOSTING (pivot points)
        104.18.2.1 -> 12 hosts

      HIGH-VALUE TARGETS
        admin.target.com [200] nginx
        jenkins.target.com [403] Jetty
        dev-api.target.com [200] Next.js

## Architecture

Passive sources run in parallel, feed into async DNS resolution (semaphore-throttled to 50 concurrent), then async HTTP probing (30 concurrent), then graph construction and SQLite diffing.

## License

MIT. For authorized security testing and bug bounty programs only.
