rule nltest
{
    meta:
        description = "Detection patterns for the tool 'nltest' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nltest"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string1 = /nltest\s\/all_trusts/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string2 = /nltest\s\/dclist/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string3 = /nltest\s\/domain_trusts/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string4 = /nltest\s\-dsgetdc/ nocase ascii wide

    condition:
        any of them
}
