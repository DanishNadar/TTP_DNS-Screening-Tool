"""
Cloudflare DoH TXT lookup (SPF / DMARC / DKIM)

Usage:
  python TTP_CloudflareDoH.py example.com
  python TTP_CloudflareDoH.py example.com other.org --selectors selector1 selector2
  python TTP_CloudflareDoH.py example.com --json
"""

import sys, argparse, json, urllib.parse, urllib.request

DEFAULT_SELECTORS = [
    "selector1","selector2","default","google","s1","s2","k1","k2",
    "fm1","fm2","fm3","pm","pm-bounces","mandrill","mandrill1","mandrill2",
    "amazonses","mail","scph","scph1","scph2","hs1","hs2","zoho","zohomail","krs","kl"
]

CF_DOH_URL = "https://cloudflare-dns.com/dns-query"

def doh_txt_cloudflare(name: str, timeout: float = 6.0):
    """
    Query TXT via Cloudflare DoH (application/dns-json).
    Returns a list of TXT strings with concatenated chunks.
    """
    params = urllib.parse.urlencode({"name": name, "type": "TXT"})
    url = f"{CF_DOH_URL}?{params}"
    req = urllib.request.Request(
        url,
        headers={"accept": "application/dns-json", "user-agent": "curl/8"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    out = []
    for ans in (data.get("Answer") or []):
        if ans.get("type") == 16:  # TXT
            raw = ans.get("data", "")
            # Join quoted TXT chunks: "\"part1\" \"part2\"" -> "part1part2"
            parts, cur, q = [], "", False
            for ch in raw:
                if ch == '"':
                    q = not q
                    if not q:
                        parts.append(cur); cur = ""
                elif q:
                    cur += ch
            out.append("".join(parts) if parts else raw.strip('"'))
    return out

def first_spf(txts):
    for t in txts:
        if str(t).lower().startswith("v=spf1"):
            return t
    return None

def scan_domain(domain: str, selectors):
    res = {"domain": domain, "spf": None, "dmarc": None, "dkim": {}}

    # SPF
    spf_txts = doh_txt_cloudflare(domain)
    res["spf"] = first_spf(spf_txts)

    # DMARC
    dmarc_txts = doh_txt_cloudflare(f"_dmarc.{domain}")
    res["dmarc"] = dmarc_txts[0] if dmarc_txts else None

    # DKIM
    for sel in selectors:
        txts = doh_txt_cloudflare(f"{sel}._domainkey.{domain}")
        if any("v=dkim1" in t.lower() for t in txts):
            res["dkim"][sel] = txts

    return res

def print_human(res):
    d = res["domain"]
    print(f"=== SPF Record ({d}) ===")
    print(res["spf"] or "No SPF found")
    print()
    print(f"=== DMARC Record (_dmarc.{d}) ===")
    print(res["dmarc"] or "No DMARC found")
    print()
    print(f"=== DKIM Records (common selectors, {d}) ===")
    if res["dkim"]:
        for sel, recs in res["dkim"].items():
            print(f"[{sel}] {', '.join(recs)}")
    else:
        print("No DKIM selectors found (from common list)")
    print()

def main():
    ap = argparse.ArgumentParser(description="Check SPF/DMARC/DKIM via Cloudflare DoH")
    ap.add_argument("domains", nargs="+", help="domain(s) to check")
    ap.add_argument("--selectors", nargs="*", default=DEFAULT_SELECTORS, help="DKIM selectors to try")
    ap.add_argument("--json", action="store_true", help="emit JSON (one object per domain)")
    args = ap.parse_args()

    results = []
    for raw in args.domains:
        domain = raw.strip().lower().rstrip(".")
        try:
            res = scan_domain(domain, args.selectors)
        except Exception as e:
            res = {"domain": domain, "error": str(e)}
        results.append(res)

    if args.json:
        # Print JSONL (one line per domain) for easy piping/jq
        for res in results:
            print(json.dumps(res, separators=(",", ":")))
    else:
        for res in results:
            if "error" in res:
                print(f"=== {res['domain']} ===\nERROR: {res['error']}\n")
            else:
                print_human(res)

if __name__ == "__main__":
    main()
