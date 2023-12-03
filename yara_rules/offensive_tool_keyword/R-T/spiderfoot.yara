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
        $string1 = /.{0,1000}\s\.\/sf\.py\s\-l\s127\.0\.0\.1:5001.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string2 = /.{0,1000}\/sfp_openphish\.py.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string3 = /.{0,1000}\/sfp_spider\.py.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string4 = /.{0,1000}\/SpiderFoot\-.{0,1000}\.log\.cs.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string5 = /.{0,1000}\/SpiderFoot\.csv.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string6 = /.{0,1000}\/spiderfoot\.git.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string7 = /.{0,1000}\/subdomains\-10000\.txt.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string8 = /.{0,1000}dicts.{0,1000}generic\-usernames\.txt.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string9 = /.{0,1000}sfp_portscan_tcp\.py.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string10 = /.{0,1000}sfp_torexits\.py.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string11 = /.{0,1000}smicallef\/spiderfoot.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string12 = /.{0,1000}\-SpiderFoot\-correlations\.csv.{0,1000}/ nocase ascii wide
        // Description: The OSINT Platform for Security Assessments
        // Reference: https://www.spiderfoot.net/
        $string13 = /.{0,1000}spiderfoot\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
