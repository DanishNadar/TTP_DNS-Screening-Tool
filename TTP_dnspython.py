import dns.resolver

DOMAIN = "transitionparadigm.com"
RESOLVERS = ["1.1.1.1", "8.8.8.8"]  # Cloudflare & Google
resolver = dns.resolver.Resolver(configure=True)
resolver.nameservers = RESOLVERS
resolver.timeout = 3.0
resolver.lifetime = 4.0

def txt(name):
    try:
        return ["".join([p.decode() for p in r.strings]) for r in resolver.resolve(name, "TXT")]
    except Exception:
        return []

# SPF (root TXT that starts with v=spf1)
spf = [t for t in txt(DOMAIN) if t.lower().startswith("v=spf1")]
print("SPF:", spf[:1])

# DMARC (_dmarc subdomain)
print("DMARC:", txt(f"_dmarc.{DOMAIN}"))

# DKIM (you must try selectors; DNS can’t list them)
COMMON_SELECTORS = ["selector1","selector2","default","google","s1","s2","k1","k2","fm1","fm2","fm3","pm","pm-bounces","mandrill","mandrill1","mandrill2","amazonses","mail","scph","scph1","scph2","hs1","hs2","zoho","zohomail","krs","kl"]
dkim_found = {}
for s in COMMON_SELECTORS:
    recs = txt(f"{s}._domainkey.{DOMAIN}")
    if any("v=DKIM1" in r.upper() for r in recs):
        dkim_found[s] = recs
print("DKIM selectors found:", dkim_found)
