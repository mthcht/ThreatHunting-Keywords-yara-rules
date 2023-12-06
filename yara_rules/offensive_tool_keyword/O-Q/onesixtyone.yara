rule onesixtyone
{
    meta:
        description = "Detection patterns for the tool 'onesixtyone' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onesixtyone"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fast SNMP scanner. onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them in a fashion similar to Nmap ping sweeps
        // Reference: https://github.com/trailofbits/onesixtyone
        $string1 = /\s\-i\ssnmp\-ips\.txt\s\-c\scommunity\.txt/ nocase ascii wide
        // Description: Fast SNMP scanner. onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them in a fashion similar to Nmap ping sweeps
        // Reference: https://github.com/trailofbits/onesixtyone
        $string2 = /\sonesixtyone\.c/ nocase ascii wide
        // Description: Fast SNMP scanner. onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them in a fashion similar to Nmap ping sweeps
        // Reference: https://github.com/trailofbits/onesixtyone
        $string3 = /\/onesixtyone\/dict\.txt/ nocase ascii wide
        // Description: Fast SNMP scanner. onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them in a fashion similar to Nmap ping sweeps
        // Reference: https://github.com/trailofbits/onesixtyone
        $string4 = /onesixtyone\s\-i\s.{0,1000}\s\-c/ nocase ascii wide
        // Description: Fast SNMP scanner. onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them in a fashion similar to Nmap ping sweeps
        // Reference: https://github.com/trailofbits/onesixtyone
        $string5 = /onesixtyone\.1/ nocase ascii wide
        // Description: Fast SNMP scanner. onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them in a fashion similar to Nmap ping sweeps
        // Reference: https://github.com/trailofbits/onesixtyone
        $string6 = /onesixtyone\.git/ nocase ascii wide
        // Description: Fast SNMP scanner. onesixtyone takes a different approach to SNMP scanning. It takes advantage of the fact that SNMP is a connectionless protocol and sends all SNMP requests as fast as it can. Then the scanner waits for responses to come back and logs them in a fashion similar to Nmap ping sweeps
        // Reference: https://github.com/trailofbits/onesixtyone
        $string7 = /trailofbits\/onesixtyone/ nocase ascii wide

    condition:
        any of them
}
