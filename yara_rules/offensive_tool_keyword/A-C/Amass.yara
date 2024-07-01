rule Amass
{
    meta:
        description = "Detection patterns for the tool 'Amass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Amass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/OWASP/Amass
        $string1 = /caffix.{0,1000}amass/ nocase ascii wide
        // Description: In-depth subdomain enumeration tool that performs scraping. recursive brute forcing06/01/2021 crawling of web archives06/01/2021 name altering and reverse DNS sweeping
        // Reference: https://github.com/OWASP/Amass
        $string2 = /caffix\/amass/ nocase ascii wide
        // Description: In-depth subdomain enumeration tool that performs scraping. recursive brute forcing06/01/2021 crawling of web archives06/01/2021 name altering and reverse DNS sweeping
        // Reference: https://github.com/OWASP/Amass
        $string3 = /install\samass/ nocase ascii wide
        // Description: The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.
        // Reference: https://github.com/caffix/amass
        $string4 = /OWASP.{0,1000}Amass/ nocase ascii wide

    condition:
        any of them
}
