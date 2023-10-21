rule ifconfig
{
    meta:
        description = "Detection patterns for the tool 'ifconfig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ifconfig"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: change mac address with ifconfig
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /ifconfig\s.*\shw\sether\s/ nocase ascii wide
        // Description: changing mac address with ifconfig
        // Reference: N/A
        $string2 = /ifconfig\s.*\shw\sether\s.*:.*:/ nocase ascii wide

    condition:
        any of them
}