rule dnscan
{
    meta:
        description = "Detection patterns for the tool 'dnscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string1 = /\sdnscan\.py/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string2 = /\/dnscan\.git/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string3 = /\/dnscan\.py/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string4 = /\/subdomains\.txt/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string5 = /\\dnscan\.py/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string6 = /dnscan\-master/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string7 = /rbsec\/dnscan/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string8 = /subdomains\-100\.txt/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string9 = /subdomains\-1000\.txt/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string10 = /subdomains\-10000\.txt/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string11 = /subdomains\-500\.txt/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string12 = /subdomains\-uk\-1000\.txt/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string13 = /subdomains\-uk\-500\.txt/ nocase ascii wide

    condition:
        any of them
}
