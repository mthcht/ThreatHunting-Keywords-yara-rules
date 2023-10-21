rule xxd
{
    meta:
        description = "Detection patterns for the tool 'xxd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xxd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ICMP Tunneling One Liner
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /xxd\s\-p\s\-c\s4\s\/.*\s\|\swhile\sread\sline.*\sdo\sping\s\-c\s1\s\-p\s/ nocase ascii wide

    condition:
        any of them
}