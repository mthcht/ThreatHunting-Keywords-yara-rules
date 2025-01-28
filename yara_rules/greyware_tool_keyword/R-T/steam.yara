rule steam
{
    meta:
        description = "Detection patterns for the tool 'steam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "steam"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Steam profiles have been leveraged to host payload addresses for malware delivery - making them a potential threat vector in corporate environments. This tactic can serve as a valuable hunting tip for threat detection efforts
        // Reference: N/A
        $string1 = /https\:\/\/steamcommunity\.com\/profiles\// nocase ascii wide

    condition:
        any of them
}
