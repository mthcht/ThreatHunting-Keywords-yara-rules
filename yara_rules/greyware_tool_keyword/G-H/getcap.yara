rule Getcap
{
    meta:
        description = "Detection patterns for the tool 'Getcap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Getcap"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Enumerating File Capabilities with Getcap
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /getcap\s\-r\s\/\s2\>\/dev\/null/ nocase ascii wide

    condition:
        any of them
}
