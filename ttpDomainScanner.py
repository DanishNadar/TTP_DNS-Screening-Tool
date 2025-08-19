import logging
import sys
import dns.resolver
import re
import openpyxl

logFileName = "ttpDomainScannerOutput.md"

# Formatter for Markdown file
class MarkdownFileFormatter(logging.Formatter):
    def format(self, record):
        msg = record.getMessage()
        level = record.levelname

        if "Starting DNS Email Authentication Scan" in msg:
            return "# DNS Email Authentication Scan\n"
        elif "Scan Complete" in msg:
            return "\n---\n**Scan complete.**\n"
        elif "Scanning domain:" in msg:
            domain = msg.split(":")[1].strip(" =")
            return f"\n## Scanning `{domain}`\n"
        elif "Finished scanning" in msg:
            return ""  # skip this line
        elif level == "INFO":
            return f"- {msg}"
        elif level == "WARNING":
            return f"- Warning: {msg}"
        elif level == "ERROR":
            return f"- **ERROR:** {msg}"
        else:
            return f"- {msg}"

# ANSI formatter for console
class ConsoleFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)

        if "Starting DNS Email Authentication Scan" in record.msg:
            return f"\033[1;37m\033[1m{msg}\033[0m"  # Bold white
        elif "Scan Complete\n" in record.msg:
            return f"\033[1;37m\033[1m{msg}\033[0m"  # Bold white
        elif "Scanning domain:" in record.msg:
            return f"\033[1;32m\033[1m{msg}\033[0m"  # Bold green
        elif "Finished scanning" in record.msg:
            return f"\033[1;34m\033[1m{msg}\033[0m"  # Bold blue
        elif "Failed to load or process domains.xlsx" in record.msg:
            return f"\033[1;31m\033[1m{msg}\033[0m"  # Bold red
        elif "Scan Complete" in record.msg:
            return f"\033[1;37m\033[1m{msg}\033[0m"  # Bold white
        return msg

# Set up handlers
consoleHandler = logging.StreamHandler(sys.stdout)
consoleHandler.setFormatter(ConsoleFormatter("%(asctime)s [%(levelname)s] %(message)s"))

fileHandler = logging.FileHandler(logFileName, mode='w')
fileHandler.setFormatter(MarkdownFileFormatter())

logging.basicConfig(level=logging.INFO, handlers=[consoleHandler, fileHandler])

commonSelectors = [
    "selector1", "selector2", "default", "google", "s1", "s2",
    "k1", "k2", "fm1", "fm2", "pm", "mandrill", "amazonses", "mail", "zohomail"
]

def parseSpfMechanisms(spfRecord):
    mechanisms = re.findall(r"(ip4:[\d\.\/]+|ip6:[\da-fA-F:\/]+|include:[^\s]+)", spfRecord)
    seen = set()
    duplicates = []
    for mech in mechanisms:
        if mech in seen:
            duplicates.append(mech)
        seen.add(mech)
    return duplicates

def checkSpf(domain):
    logging.info(f"Checking SPF for {domain}")
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for r in answers:
            txtRecord = "".join([s.decode() if isinstance(s, bytes) else s for s in r.strings])
            if txtRecord.startswith("v=spf1"):
                logging.info(f"SPF Record: `{txtRecord}`")
                duplicates = parseSpfMechanisms(txtRecord)
                if duplicates:
                    logging.warning(f"SPF contains duplicate mechanisms: {duplicates}")
                return
        logging.warning("No SPF record found.")
    except Exception as e:
        logging.error(f"Error checking SPF: {e}")

def checkDmarc(domain):
    dmarcDomain = f"_dmarc.{domain}"
    logging.info(f"Checking DMARC for {dmarcDomain}")
    try:
        answers = dns.resolver.resolve(dmarcDomain, "TXT", lifetime=5)
        for r in answers:
            txtRecord = "".join([s.decode() if isinstance(s, bytes) else s for s in r.strings])
            if txtRecord.startswith("v=DMARC1"):
                logging.info(f"DMARC Record: `{txtRecord}`")
                policyMatch = re.search(r"p=(\w+)", txtRecord)
                subPolicyMatch = re.search(r"sp=(\w+)", txtRecord)
                ruaMatch = re.search(r"rua=mailto:([^;\s]+)", txtRecord)

                if policyMatch:
                    policy = policyMatch.group(1).lower()
                    if policy != "reject":
                        logging.warning(f"DMARC policy is weak (p={policy}). Consider using 'reject'.")
                else:
                    logging.warning("No DMARC policy (p=) found.")

                if subPolicyMatch:
                    sp = subPolicyMatch.group(1).lower()
                    if sp != "reject":
                        logging.warning(f"Subdomain DMARC policy is weak (sp={sp}). Consider using 'reject'.")
                else:
                    logging.info("No subdomain policy (sp=) set.")

                if not ruaMatch:
                    logging.warning("No RUA tag configured for aggregate report collection.")
                return
        logging.warning("No DMARC record found.")
    except Exception as e:
        logging.error(f"Error checking DMARC: {e}")

def checkDkim(domain):
    logging.info(f"Checking DKIM for {domain}")
    found = False
    for selector in commonSelectors:
        record = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(record, "TXT", lifetime=5)
            for r in answers:
                txtRecord = "".join([s.decode() if isinstance(s, bytes) else s for s in r.strings])
                if txtRecord.startswith("v=DKIM1"):
                    logging.info(f"DKIM Record found for selector `{selector}`: `{txtRecord[:75]}...`")
                    found = True
        except:
            continue
    if not found:
        logging.warning("No DKIM records found among common selectors.")

def scanDomain(domain):
    logging.info(f"Scanning domain: {domain}")
    checkSpf(domain)
    checkDmarc(domain)
    checkDkim(domain)
    logging.info(f"Finished scanning {domain}\n")

def loadDomainsFromExcel(filePath):
    workbook = openpyxl.load_workbook(filePath)
    sheet = workbook.active
    domains = []
    for row in sheet.iter_rows(min_row=2, values_only=True):
        domain = row[0]
        if domain and isinstance(domain, str):
            domains.append(domain.strip())
    return domains

if __name__ == "__main__":
    logging.info("Starting DNS Email Authentication Scan\n")
    try:
        domainList = loadDomainsFromExcel("domains.xlsx")
        for domain in domainList:
            scanDomain(domain)
    except Exception as e:
        logging.error(f"Failed to load or process domains.xlsx: {e}")
    logging.info("Scan Complete")
