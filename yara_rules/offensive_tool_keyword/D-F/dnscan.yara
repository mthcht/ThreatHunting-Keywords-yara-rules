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
        $string1 = /.{0,1000}\sdnscan\.py.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string2 = /.{0,1000}\/dnscan\.git.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string3 = /.{0,1000}\/dnscan\.py.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string4 = /.{0,1000}\/subdomains\.txt.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string5 = /.{0,1000}\\dnscan\.py.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string6 = /.{0,1000}dnscan\-master.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string7 = /.{0,1000}rbsec\/dnscan.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string8 = /.{0,1000}subdomains\-100\.txt.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string9 = /.{0,1000}subdomains\-1000\.txt.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string10 = /.{0,1000}subdomains\-10000\.txt.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string11 = /.{0,1000}subdomains\-500\.txt.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string12 = /.{0,1000}subdomains\-uk\-1000\.txt.{0,1000}/ nocase ascii wide
        // Description: dnscan is a python wordlist-based DNS subdomain scanner.
        // Reference: https://github.com/rbsec/dnscan
        $string13 = /.{0,1000}subdomains\-uk\-500\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
