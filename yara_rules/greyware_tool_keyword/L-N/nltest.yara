rule nltest
{
    meta:
        description = "Detection patterns for the tool 'nltest' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nltest"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Get the list of domain controllers for the specified domain
        // Reference: N/A
        $string1 = "nltest  /dclist:" nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string2 = "nltest /all_trusts" nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string3 = "nltest /dclist" nocase ascii wide
        // Description: Dump Domain Trust Information
        // Reference: N/A
        $string4 = "nltest /domain_trusts /v" nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string5 = "nltest /domain_trusts" nocase ascii wide
        // Description: Force a re-discovery of Domain Controller
        // Reference: N/A
        $string6 = /nltest\s\/dsgetdc\:.{0,1000}\s\/force/ nocase ascii wide
        // Description: Force a re-discovery of trusted domains
        // Reference: N/A
        $string7 = /nltest\s\/dsgetdc\:.{0,1000}\s\/force/ nocase ascii wide
        // Description: Force a re-authentication on the secure channel
        // Reference: N/A
        $string8 = "nltest /sc_reset /force" nocase ascii wide
        // Description: List information about all trusted domains from a specific server
        // Reference: N/A
        $string9 = /nltest\s\/server\:.{0,1000}\s\/domain_trusts/ nocase ascii wide
        // Description: Check all trusted domains of a specific server (verbose mode)
        // Reference: N/A
        $string10 = /nltest\s\/server\:.{0,1000}\s\/trusted_domains\s\/v/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string11 = "nltest -dsgetdc" nocase ascii wide

    condition:
        any of them
}
