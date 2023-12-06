rule domainhunter
{
    meta:
        description = "Detection patterns for the tool 'domainhunter' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "domainhunter"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string1 = /\sdomainhunter\s/ nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string2 = /\s\-\-keyword\s.{0,1000}\s\-\-check\s\-\-ocr\s.{0,1000}\s\-\-alexa/ nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string3 = /\/domainhunter/ nocase ascii wide
        // Description: Domain name selection is an important aspect of preparation for penetration tests and especially Red Team engagements. Commonly. domains that were used previously for benign purposes and were properly categorized can be purchased for only a few dollars. Such domains can allow a team to bypass reputation based web filters and network egress restrictions for phishing and C2 related tasks.This Python based tool was written to quickly query the Expireddomains.net search engine for expired/available domains with a previous history of use. It then optionally queries for domain reputation against services like Symantec Site Review (BlueCoat). IBM X-Force. and Cisco Talos. The primary tool output is a timestamped HTML table style report.
        // Reference: https://github.com/threatexpress/domainhunter
        $string4 = /domainhunter/ nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string5 = /domainhunter\.py/ nocase ascii wide
        // Description: Checks expired domains for categorization/reputation and Archive.org history to determine good candidates for phishing and C2 domain names 
        // Reference: https://github.com/threatexpress/domainhunter
        $string6 = /downloadMalwareDomains/ nocase ascii wide

    condition:
        any of them
}
