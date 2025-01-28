rule subfinder
{
    meta:
        description = "Detection patterns for the tool 'subfinder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "subfinder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SubFinder is a subdomain discovery tool that discovers valid subdomains for any target using passive online sources.
        // Reference: https://github.com/subfinder/subfinder
        $string1 = "subfinder" nocase ascii wide

    condition:
        any of them
}
