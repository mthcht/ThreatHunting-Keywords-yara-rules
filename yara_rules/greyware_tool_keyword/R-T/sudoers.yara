rule sudoers
{
    meta:
        description = "Detection patterns for the tool 'sudoers' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudoers"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: use SUDO without password
        // Reference: N/A
        $string1 = /echo\s.*\sALL\=\(ALL\)\sNOPASSWD:\sALL.*\s\>\>\/etc\/sudoers/ nocase ascii wide
        // Description: use SUDO without password
        // Reference: N/A
        $string2 = /echo\s.*\sALL\=NOPASSWD:\s\/bin\/bash.*\s\>\>\/etc\/sudoers/ nocase ascii wide

    condition:
        any of them
}