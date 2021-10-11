# PyZoneValidator

```
zv = zoneValidator()
from pprint import pprint
pprint(zv.validate('dnssec-failed.org', fail_if_not_signed=False))

# Output:
#{'errors': [DNSSEC_DS_AND_DNSKEY_RECORD_DO_NOT_MATCH: DNSSEC: DS and DNSKEY key do not align for zone 'dnssec-failed.org'. [dns102.comcast.net.],
#            DNSSEC_DS_AND_DNSKEY_RECORD_DO_NOT_MATCH: DNSSEC: DS and DNSKEY key do not align for zone 'dnssec-failed.org'. [dns101.comcast.net.],
#            DNSSEC_DS_AND_DNSKEY_RECORD_DO_NOT_MATCH: DNSSEC: DS and DNSKEY key do not align for zone 'dnssec-failed.org'. [dns105.comcast.net.],
#            DNSSEC_DS_AND_DNSKEY_RECORD_DO_NOT_MATCH: DNSSEC: DS and DNSKEY key do not align for zone 'dnssec-failed.org'. [dns103.comcast.net.],
#            DNSSEC_DS_AND_DNSKEY_RECORD_DO_NOT_MATCH: DNSSEC: DS and DNSKEY key do not align for zone 'dnssec-failed.org'. [dns104.comcast.net.]],
# 'warnings': []}
```
