rule vncpwdump
{
    meta:
        description = "Detection patterns for the tool 'vncpwdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncpwdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: vnc password sniffer
        // Reference: https://www.codebus.net/d-2v0u.html
        $string1 = /vncdumpdll/ nocase ascii wide
        // Description: vnc password sniffer
        // Reference: https://www.codebus.net/d-2v0u.html
        $string2 = /vncpwdump\./ nocase ascii wide

    condition:
        any of them
}
