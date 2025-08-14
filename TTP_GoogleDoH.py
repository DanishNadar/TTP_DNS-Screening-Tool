# MUST RUN './TTP_GoogleDoH.bash domain1.com domain2.com ...' TO RUN THIS PYTHON SCRIPT AS A SUPPLEMENT

import sys
import argparse
import urllib.parse
import urllib.request
import json

def doh_txt_google(name):
    """Fetch TXT record using Google DoH."""
    url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": name, "type": "TXT"})
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
    with urllib.request.urlopen(req, timeout=6) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    out = []
    for ans in data.get("Answer", []):
        if ans.get("type") == 16:
            row = ans.get("data", "")
            parts, cur, q = [], "", False
            for ch in row:
                if ch == '"':
                    q = not q
                    if not q:
                        parts.append(cur)
                        cur = ""
                elif q:
                    cur += ch
            out.append("".join(parts) if parts else row.strip('"'))
    return out

def first_spf(txts):
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return t
    return None

def main():
    parser = argparse.ArgumentParser(description="Check SPF, DMARC, DKIM records via Google DoH")
    parser.add_argument("domain", help="Domain name to check")
    parser.add_argument("--selectors", nargs="*", default=[])
    args = parser.parse_args()

    domain = args.domain

    # SPF
    print(f"\tSPF Record ({domain})")
    spf = first_spf(doh_txt_google(domain))
    print(spf if spf else "No SPF found")
    print()

    # DMARC
    print(f"\t DMARC Record (_dmarc.{domain}) \t")
    dmarc = doh_txt_google(f"_dmarc.{domain}")
    print("\n".join(dmarc) if dmarc else "No DMARC found")
    print()

    # DKIM
    print(f"\t DKIM Records (common selectors, {domain}) \t")
    found = False
    for sel in args.selectors:
        recs = doh_txt_google(f"{sel}._domainkey.{domain}")
        if any("v=DKIM1" in r.upper() for r in recs):
            print(f"[{sel}] {', '.join(recs)}")
            found = True
    if not found:
        print("No DKIM selectors found (from common list)")

if __name__ == "__main__":
    main()
