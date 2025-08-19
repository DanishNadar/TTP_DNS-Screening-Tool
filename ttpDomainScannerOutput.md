# DNS Email Authentication Scan


## Scanning `google.com`

- Checking SPF for google.com
- SPF Record: `v=spf1 include:_spf.google.com ~all`
- Checking DMARC for _dmarc.google.com
- DMARC Record: `v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com`
- No subdomain policy (sp=) set.
- Checking DKIM for google.com
- Warning: No DKIM records found among common selectors.


## Scanning `illinoistech.com`

- Checking SPF for illinoistech.com
- **ERROR:** Error checking SPF: The DNS response does not contain an answer to the question: illinoistech.com. IN TXT
- Checking DMARC for _dmarc.illinoistech.com
- **ERROR:** Error checking DMARC: The DNS query name does not exist: _dmarc.illinoistech.com.
- Checking DKIM for illinoistech.com
- Warning: No DKIM records found among common selectors.


## Scanning `officeproinc.com`

- Checking SPF for officeproinc.com
- SPF Record: `v=spf1 include:spf.em.secureserver.net include:spf.protection.outlook.com include:spf.messagelabs.com -all`
- Checking DMARC for _dmarc.officeproinc.com
- DMARC Record: `v=DMARC1; p=none; rua=mailto:report@dmarc.em.secureserver.net`
- Warning: DMARC policy is weak (p=none). Consider using 'reject'.
- No subdomain policy (sp=) set.
- Checking DKIM for officeproinc.com
- Warning: No DKIM records found among common selectors.


## Scanning `transitionparadigm.com`

- Checking SPF for transitionparadigm.com
- SPF Record: `v=spf1 include:spf.protection.outlook.com ip4:70.184.161.98/32 -all`
- Checking DMARC for _dmarc.transitionparadigm.com
- DMARC Record: `v=DMARC1;  p=reject; rua=mailto:dmarc@transitionparadigm.com`
- No subdomain policy (sp=) set.
- Checking DKIM for transitionparadigm.com
- DKIM Record found for selector `selector1`: `v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnZLvwMHu7K2Is...`


## Scanning `montgomerycollege.edu`

- Checking SPF for montgomerycollege.edu
- SPF Record: `v=spf1 ip4:160.253.130.20 ip4:160.253.130.22 ip4:160.253.130.23 ip4:160.253.130.24 ip4:160.253.129.8 ip4:176.31.145.254 include:spf.protection.outlook.com include:spf.sedlv.net ~all`
- Checking DMARC for _dmarc.montgomerycollege.edu
- DMARC Record: `v=DMARC1;p=none;rua=mailto:dmarc@montgomerycollege.edu;`
- Warning: DMARC policy is weak (p=none). Consider using 'reject'.
- No subdomain policy (sp=) set.
- Checking DKIM for montgomerycollege.edu
- DKIM Record found for selector `selector1`: `v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCv0dKWR+hVAxfzLGFHq...`


---
**Scan complete.**

