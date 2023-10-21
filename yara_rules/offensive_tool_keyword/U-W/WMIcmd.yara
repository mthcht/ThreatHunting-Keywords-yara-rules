rule WMIcmd
{
    meta:
        description = "Detection patterns for the tool 'WMIcmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMIcmd"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool allows us to execute commands via WMI and get information not otherwise available via this channel.
        // Reference: https://github.com/nccgroup/WMIcmd
        $string1 = /WMIcmd/ nocase ascii wide

    condition:
        any of them
}