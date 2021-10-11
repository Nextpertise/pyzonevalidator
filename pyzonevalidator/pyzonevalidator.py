import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.rdtypes.ANY.DS
import json

class nameserver:
    name = None
    ipv4 = None
    ipv6 = None

    def __init__(self, name, ipv4=None, ipv6=None):
        self.name = name
        self.ipv4 = ipv4
        self.ipv6 = ipv6

    def __repr__(self):
        return f"{self.name}: {self.ipv4}, {self.ipv6}"

class validationError:
    zone = None
    code = None
    message = {
        'NO_NAMESERVERS': "Could not retrieve nameservers for zone '{}'.",
        'DNSSEC_NO_DS_RECORD': "DNSSEC: DS record is missing on parent zone, zone '{}' is not secure.",
        'DNSSEC_NO_DNSKEY': "DNSSEC: DNSKEY record is missing in zone, zone '{}' is not secure.",
        'DNSSEC_DS_AND_DNSKEY_RECORD_DO_NOT_MATCH': "DNSSEC: DS and DNSKEY key do not align for zone '{}'.",
        'DNSSEC_ZONE_IS_SIGNED_BUT_PARENT_ZONE_IS_NOT': "DNSSEC: Zone '{}' is signed with a DNSKEY, but the parent zone does not contain a DS record.",
        'DNSSEC_ZONE_IS_NOT_SIGNED_BUT_TLD_DOES_SUPPORT_DNSSEC': "DNSSEC: Zone '{}' is not signed, but TLD does support DNSSEC.",
        'DNSSEC_ZONE_IS_NOT_PROPERLY_SIGNED': "DNSSEC: Zone '{}' is not properly signed.",
        'DNSSEC_DNSKEY_OR_RRSIG_RECORD_MISSING': "DNSSEC: We expect both a DNSKEY and RRSIG record in result for zone '{}'.",
        'DNSSEC_CANNOT_VALIDATE_RECORD': "DNSSEC validation failed for zone '{}'.",
        'NAMESERVER_UDP_IPV4_NOT_RESPONDING': "Nameserver not responding on IPv4 and transport protocol UDP for zone '{}'.",
        'NAMESERVER_UDP_IPV6_NOT_RESPONDING': "Nameserver not responding on IPv6 and transport protocol UDP for zone '{}'."
    }
    nameserver = None

    def getMessage(self):
        return self.message[self.code].format(self.zone)

    def __init__(self, code, zone, nameserver=None):
        self.code = code
        self.zone = zone
        if nameserver:
            self.nameserver = nameserver

    def __repr__(self):
        repr = f"{self.code}: {self.getMessage()}"
        if self.nameserver:
            repr = f"{self.code}: {self.getMessage()} [{self.nameserver.name}]"
        return repr

    def __eq__(self, other):
        if (isinstance(other, validationError)):
            return self.code == other.code

class zoneValidator:
    timeout=1.0

    # parent_zone_ds_record['zone.tld'] = "DS HERE"
    parent_zone_ds_record = {}
    
    def getParentZone(self, zone):
        zoneList = zone.split('.')
        zoneList.pop(0)
        parentzone = '.'.join(zoneList)
        return parentzone

    def filterListItems(self, needle, filterList):
        removeIndexList = []
        for idx, value in enumerate(filterList):
            if(value == needle):
                removeIndexList.append(idx)
        removeIndexList.sort(reverse=True)
        for idx in removeIndexList:
            filterList.pop(idx)
        return filterList

    def getNameservers(self, zone):
        """Return list[nameservers] or an validationError."""
        nameservers = []
        errors = []
        warnings = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        try:
            response = resolver.resolve(dns.name.from_text(zone), dns.rdatatype.NS)
        except dns.resolver.NXDOMAIN:
            errors.append(validationError('NO_NAMESERVERS', zone))
            return errors, warnings, nameservers
        for i in response.rrset:
            name = i.to_text()
            ns = nameserver(name)
            append = False
            try:
                ns.ipv4 = resolver.resolve(dns.name.from_text(i.to_text()), dns.rdatatype.A).rrset[0].to_text()
                append = True
            except dns.resolver.NoAnswer:
                ns.ipv4 = None
                errors.append(validationError('NAMESERVER_UDP_IPV4_NOT_RESPONDING', zone, ns))
            try:
                ns.ipv6 = resolver.resolve(dns.name.from_text(i.to_text()), dns.rdatatype.AAAA).rrset[0].to_text()
            except dns.resolver.NoAnswer:
                ns.ipv6 = None
                warnings.append(validationError('NAMESERVER_UDP_IPV6_NOT_RESPONDING', zone, ns))
            if append:
                nameservers.append(ns)
        return errors, warnings, nameservers

    def getDSByParentZone(self, zone):
        # Get nameservers for the parent zone
        parentZone = self.getParentZone(zone)
        errors, warnings, nameservers = self.getNameservers(parentZone)
        lastNameserverAddr = nameservers[-1]
        
        # Check if parent supports DNSSEC
        parent_ds_result = self.getDSFromDNSKeyByZone(parentZone, lastNameserverAddr)
        if isinstance(parent_ds_result, validationError):
            warnings.append(parent_ds_result)
            return errors, warnings, False
        if isinstance(parent_ds_result, dns.rdtypes.ANY.DS.DS):
           self.parent_zone_ds_record[parentZone] = parent_ds_result
    
        # get DS for zone
        request = dns.message.make_query(dns.name.from_text(zone),
                                         dns.rdatatype.DS)
        # send the query
        response = dns.query.udp(request, lastNameserverAddr.ipv4, timeout=self.timeout)
        
        if response.answer:
            if isinstance(response.answer[0], dns.rrset.RRset):
                if isinstance(response.answer[0][0], dns.rdtypes.ANY.DS.DS):
                    return errors, warnings, response.answer[0][0]
        errors.append(validationError('DNSSEC_NO_DS_RECORD', zone, lastNameserverAddr))
        return errors, warnings, False

    # Future reference: this is how you can read the invidual fields from the DS key:    
    #   print(response.answer[0][0].to_text())
    #   print(f'key_tag: {response.answer[0][0].key_tag}')
    #   print(f'algorithm: {response.answer[0][0].algorithm}')
    #   print(f'digest_type: {response.answer[0][0].digest_type}')
    #   digestHex = dns.rdata._hexify(response.answer[0][0].digest, chunksize=128)
    #   print(f'digest: {digestHex}')

    def getDSFromDNSKeyByZone(self, zone, nameserver, digest_type='SHA256'):
        """Return DS as string or validationError"""
        # get DNSKEY for zone
        request = dns.message.make_query(dns.name.from_text(zone), dns.rdatatype.DNSKEY, want_dnssec=True)
        # send the query
        response = dns.query.udp(request, nameserver.ipv4, timeout=self.timeout)
        if response.rcode() != 0:
            # Query failed (Server error or no DNSKEY record found)
            return validationError('DNSSEC_NO_DNSKEY', zone, nameserver)
        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY), 
        # but we will fail on a missing DNSKEY. RRSIG record is checked in validate_rrsig_for_zone_by_nameserver().
        answer = response.answer
        
        # This is a work-around-mess. We look for key with flag 257, if not found we take the 256. 
        # It works, but I guess this implementation is not compliant with it's RFC.
        dnskey = False
        for i in answer:
            if isinstance(i[0], dns.rdtypes.ANY.DNSKEY.DNSKEY):
                for key in i:
                    if key.flags == 257:
                        dnskey = key
        if dnskey:
            name = dns.name.from_text(zone)
            return dns.dnssec.make_ds(name, dnskey, digest_type)
        else:
            for i in answer:
                if isinstance(i[0], dns.rdtypes.ANY.DNSKEY.DNSKEY):
                    for key in i:
                        if key.flags == 256:
                            dnskey = key
        if dnskey:
            name = dns.name.from_text(zone)
            return dns.dnssec.make_ds(name, dnskey, digest_type)
        
        return validationError('DNSSEC_NO_DNSKEY', zone, nameserver)

    def validate_rrsig_for_zone_by_nameserver(self, zone, nameserver):
        # get DNSKEY for zone
        request = dns.message.make_query(dns.name.from_text(zone),
                                         dns.rdatatype.DNSKEY,
                                         want_dnssec=True)
        # send the query
        response = dns.query.udp(request, nameserver.ipv4, timeout=self.timeout)
        if response.rcode() != 0:
            # Query failed (Server error or no DNSKEY record found)
            return validationError('DNSSEC_NO_DNSKEY', zone, nameserver)
        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
        answer = response.answer
        if len(answer) != 2:
            return validationError('DNSSEC_DNSKEY_OR_RRSIG_RECORD_MISSING', zone, nameserver)
        # the DNSKEY should be self signed, validate it
        name = dns.name.from_text(zone)
        try:
            # Sort order of RRset in list[answer]
            for i in answer:
                if "RRSIG DNSKEY" in str(i):
                    rrsig = i
                else:
                    dnskey = i
            answer[0] = dnskey
            answer[1] = rrsig
            dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
        except dns.dnssec.ValidationFailure as e:
            return validationError('DNSSEC_CANNOT_VALIDATE_RECORD', zone, nameserver)
        else:
            return None

    def validateZoneOnSingleNameserver(self, zone, nameserver, fail_if_not_signed):
        errors = []
        if self.parent_zone_ds_record[zone] and isinstance(self.parent_zone_ds_record[zone], dns.rdtypes.ANY.DS.DS):
            # TODO: Pass digest_type in the correct way, currently we assume SHA256.
            zone_ds_result = self.getDSFromDNSKeyByZone(zone, nameserver)
            if isinstance(zone_ds_result, validationError):
                errors.append(zone_ds_result)
                return errors
            if zone_ds_result:
                if self.parent_zone_ds_record[zone] == zone_ds_result:
                    # Zone is secure, execute next check, valide rrsig record
                    rrsig_check_result = self.validate_rrsig_for_zone_by_nameserver(zone, nameserver)
                    if rrsig_check_result:
                        errors.append(rrsig_check_result)
                else:
                    errors.append(validationError('DNSSEC_DS_AND_DNSKEY_RECORD_DO_NOT_MATCH', zone, nameserver))
                    return errors
            else:
                errors.append(validationError('DNSSEC_ZONE_IS_NOT_PROPERLY_SIGNED', zone, nameserver))
        else:
            zone_ds = self.getDSFromDNSKeyByZone(zone, nameserver)
            if zone_ds and isinstance(zone_ds, dns.rdtypes.ANY.DS.DS):
                errors.append(validationError('DNSSEC_ZONE_IS_SIGNED_BUT_PARENT_ZONE_IS_NOT', zone, nameserver))
            else:
                if fail_if_not_signed:
                    if self.getParentZone(zone) in self.parent_zone_ds_record and self.parent_zone_ds_record[self.getParentZone(zone)]:
                        errors.append(validationError('DNSSEC_ZONE_IS_NOT_SIGNED_BUT_TLD_DOES_SUPPORT_DNSSEC', zone, nameserver))
        return errors

    def validate(self, zone, fail_if_not_signed=False):
        errors, warnings, nameserverResult = self.getNameservers(zone)

        if zone not in self.parent_zone_ds_record.keys():
            e, w, self.parent_zone_ds_record[zone] = self.getDSByParentZone(zone)
            errors = errors + e
            warnings = warnings + w
        if isinstance(self.parent_zone_ds_record[zone], validationError):
            errors.append(self.parent_zone_ds_record[zone])

        if nameserverResult and isinstance(nameserverResult, validationError):
            errors.append(nameserverResult)
        else:
            for nameserver in nameserverResult:
                nameserverResult = self.validateZoneOnSingleNameserver(zone, nameserver, fail_if_not_signed)
                if nameserverResult:
                    errors = errors + nameserverResult
        if not self.parent_zone_ds_record[zone]:
            # There is not DNSSEC, so we should not return the DNSSEC_NO_DS_RECORD error.
            errors = self.filterListItems(validationError('DNSSEC_NO_DS_RECORD', zone), errors)

        returnDict = {'errors': errors, 'warnings': warnings}
        return returnDict
