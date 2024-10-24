rule Cmdkey
{
    meta:
        description = "Detection patterns for the tool 'Cmdkey' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cmdkey"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: List Saved Credentials
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-290a
        $string1 = /Cmdkey\s\/list/ nocase ascii wide

    condition:
        any of them
}
