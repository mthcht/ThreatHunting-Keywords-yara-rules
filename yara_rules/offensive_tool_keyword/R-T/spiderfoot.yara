rule spiderfoot
{
    meta:
        description = "Detection patterns for the tool 'spiderfoot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spiderfoot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string1 = /\s\.\/sf\.py\s\-l\s127\.0\.0\.1\:5001/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string2 = /\/sfp_openphish\.py/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string3 = /\/sfp_spider\.py/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string4 = /\/SpiderFoot\-.{0,1000}\.log\.cs/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string5 = /\/SpiderFoot\.csv/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string6 = /\/spiderfoot\.git/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string7 = /\/subdomains\-10000\.txt/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string8 = /dicts.{0,1000}generic\-usernames\.txt/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string9 = /sfp_portscan_tcp\.py/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string10 = /sfp_torexits\.py/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string11 = /smicallef\/spiderfoot/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string12 = /\-SpiderFoot\-correlations\.csv/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string13 = /spiderfoot\-master/ nocase ascii wide

    condition:
        any of them
}
